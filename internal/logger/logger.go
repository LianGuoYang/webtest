package logger

import (
	"context"
	"log/slog"
	"os"
)

type LoggerKey struct{}

var Logger *slog.Logger

func init() {
	file, err := os.OpenFile(
		"server.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0666,
	)
	if err != nil {
		panic("failed to open log file: " + err.Error())
	}

	handler := slog.NewJSONHandler(file, nil)
	Logger = slog.New(handler)
}

func GetLogger(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(LoggerKey{}).(*slog.Logger); ok {
		return l
	}
	return Logger
}
