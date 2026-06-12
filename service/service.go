package service

// ControllerInterface is implemented by every node controller.
type ControllerInterface interface {
	Start() error
	Close() error
}

// TriggerInterface allows the Reverb WebSocket layer to wake a controller
// immediately rather than waiting for the next poll interval.
type TriggerInterface interface {
	TriggerNodeSync()
	TriggerSubscriptionSync()
	GetNodeID() int
}
