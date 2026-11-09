package app

const (
	// Name — имя приложения: папка данных, задача автозапуска, User-Agent.
	Name = "Gust"
	// DefaultPort — порт локального интерфейса по умолчанию.
	DefaultPort = 18765
)

// Version — версия, видна в интерфейсе; при сборке релиза подставляется из тега (-X).
var Version = "0.7.3"
