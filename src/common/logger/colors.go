package logger

type Color string

const (
	ColorYellow  Color = "\u001b[33m"
	ColorBlue    Color = "\u001b[34m"
	ColorMagenta Color = "\u001b[35m"
	ColorCyan    Color = "\u001b[36m"
	ColorReset   Color = "\u001b[0m"
)
