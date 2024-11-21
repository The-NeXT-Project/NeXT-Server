package service

// Service is the interface of all the services running in the panel
type Service interface {
	Start() error
	Close() error
	Restart
}

// Restart the service
type Restart interface {
	Start() error
	Close() error
}
