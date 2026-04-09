package service

type ControllerInterface interface {
    Start() error
    Close() error
}