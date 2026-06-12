package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	_ "github.com/xmplusdev/xmbox/controller"
	"github.com/xmplusdev/xmbox/instance"
)

var errReload = errors.New("reload")

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use: "XMBox",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				log.Fatal(err)
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file for XMBox.")
}

// Execute is the entry point called from main.go.
func Execute() error {
	return rootCmd.Execute()
}

func getConfig() (*viper.Viper, error) {
	config := viper.New()
	if cfgFile != "" {
		configName := path.Base(cfgFile)
		configFileExt := path.Ext(cfgFile)
		configNameOnly := strings.TrimSuffix(configName, configFileExt)
		configPath := path.Dir(cfgFile)
		config.SetConfigName(configNameOnly)
		config.SetConfigType(strings.TrimPrefix(configFileExt, "."))
		config.AddConfigPath(configPath)
	} else {
		config.SetConfigName("config")
		config.SetConfigType("yaml")
		config.AddConfigPath(".")
	}
	if err := config.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	return config, nil
}

func run() error {
	showVersion()

	restartChan := make(chan bool, 1)

	config, err := getConfig()
	if err != nil {
		return err
	}

	// Debounce timestamp shared with viper's watcher goroutine. An atomic
	// (instead of a plain time.Time) keeps the read-modify-write race-free,
	// since OnConfigChange fires from a separate goroutine.
	var lastChange atomic.Int64
	lastChange.Store(time.Now().UnixNano())

	config.OnConfigChange(func(e fsnotify.Event) {
		// viper invokes this on its own goroutine, which has no recover up
		// the stack — a panic here would otherwise crash the whole process.
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("Recovered from panic in config change handler: %v", r)
			}
		}()

		now := time.Now().UnixNano()
		prev := lastChange.Load()
		if now-prev < int64(3*time.Second) {
			return
		}
		if !lastChange.CompareAndSwap(prev, now) {
			return // a concurrent event already claimed this debounce window
		}

		log.Printf("Config file changed: %s", e.Name)
		select {
		case restartChan <- true:
		default:
		}
	})

	// Start watching only after the handler is registered, so an early
	// filesystem event can't race against an unset callback.
	config.WatchConfig()

	err = runManager(config, restartChan)
	if err == nil {
		return nil
	}

	if errors.Is(err, errReload) {
		log.Println("Restarting process...")
		exe, execErr := os.Executable()
		if execErr != nil {
			return fmt.Errorf("get executable path: %w", execErr)
		}
		if execErr = syscall.Exec(exe, os.Args, os.Environ()); execErr != nil {
			return fmt.Errorf("re-exec process: %w", execErr)
		}
		return nil
	}

	return err
}

func runManager(config *viper.Viper, restartChan chan bool) (err error) {
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	boxConfig := &instance.Config{}
	if err := config.Unmarshal(boxConfig); err != nil {
		return fmt.Errorf("parse config file %q: %w", cfgFile, err)
	}

	if boxConfig.InstanceConfig != nil && boxConfig.InstanceConfig.LogConfig != nil {
		log.SetReportCaller(boxConfig.InstanceConfig.LogConfig.Level == "debug")
	}

	i := instance.New(boxConfig)
	if err = startInstanceSafely(i); err != nil {
		return fmt.Errorf("start instance: %w", err)
	}

	defer func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("panic during instance stop: %v", r)
			}
		}()
		if stopErr := i.Stop(); stopErr != nil && err == nil {
			err = fmt.Errorf("stop instance: %w", stopErr)
		}
	}()

	runtime.GC()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer signal.Stop(osSignals)

	select {
	case sig := <-osSignals:
		log.Printf("Received signal: %v, shutting down gracefully...", sig)
		return nil
	case <-restartChan:
		return errReload
	}
}

func startInstanceSafely(i *instance.Instance) (err error) {
	if i == nil {
		return fmt.Errorf("instance is nil")
	}
	defer func() {
		if r := recover(); r != nil {
			stack := formatStack(debug.Stack())
			err = fmt.Errorf("panic during instance start: %v\nStack trace:\n%s", r, stack)
		}
	}()
	return i.Start()
}

func formatStack(stack []byte) string {
	lines := strings.Split(strings.TrimSpace(string(stack)), "\n")
	var b strings.Builder

	if len(lines) > 0 {
		b.WriteString(lines[0])
		b.WriteByte('\n')
		lines = lines[1:]
	}

	for i := 0; i+1 < len(lines); i += 2 {
		fn := strings.TrimSpace(lines[i])
		loc := strings.TrimSpace(lines[i+1])
		b.WriteString(fmt.Sprintf("  → %s\n      %s\n", fn, loc))
	}

	if len(lines)%2 != 0 {
		b.WriteString("  → ")
		b.WriteString(strings.TrimSpace(lines[len(lines)-1]))
		b.WriteByte('\n')
	}

	return b.String()
}
