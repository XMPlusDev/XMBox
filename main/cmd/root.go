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
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xmplusdev/xmbox/core"
	_ "github.com/xmplusdev/xmbox/controller"
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
	config.WatchConfig()
	return config, nil
}

func run() error {
	showVersion()

	restartChan := make(chan bool, 1)
	lastTime := time.Now()

	config, err := getConfig()
	if err != nil {
		return err
	}

	config.OnConfigChange(func(e fsnotify.Event) {
		if time.Now().After(lastTime.Add(3 * time.Second)) {
			log.Printf("Config file changed: %s", e.Name)
			lastTime = time.Now()
			select {
			case restartChan <- true:
			default:
				// Channel full, restart already pending.
			}
		}
	})

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

	boxConfig := &core.Config{}
	if err := config.Unmarshal(boxConfig); err != nil {
		return fmt.Errorf("parse config file %q: %w", cfgFile, err)
	}

	log.SetReportCaller(boxConfig.LogConfig.Level == "debug")

	i := core.New(boxConfig)
	if err = startManagerSafely(i); err != nil {
		return fmt.Errorf("start instance: %w", err)
	}

	defer func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("panic during instance stop: %v", r)
			}
		}()
		if stopErr := i.Stop(); stopErr != nil {
			if err == nil {
				err = fmt.Errorf("stop instance: %w", stopErr)
			}
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

func startManagerSafely(i *core.Instance) (err error) {
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

func Execute() error {
	return rootCmd.Execute()
}