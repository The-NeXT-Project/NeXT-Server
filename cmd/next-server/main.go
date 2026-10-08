package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	nextserver "github.com/The-NeXT-Project/NeXT-Server"
	"github.com/The-NeXT-Project/NeXT-Server/constant"
	"github.com/The-NeXT-Project/NeXT-Server/option"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/spf13/cobra"
)

var configPath string

var command = &cobra.Command{
	Use:  "next-server",
	Long: "NeXT-Server, a backend server for proxy panels",
	Run: func(cmd *cobra.Command, args []string) {
		err := run()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var versionCommand = &cobra.Command{
	Use:   "version",
	Short: "Print the version and the build tags",
	Run: func(cmd *cobra.Command, args []string) {
		tags := constant.BuildTags()
		if len(tags) == 0 {
			tags = []string{"none"}
		}
		os.Stdout.WriteString("next-server " + constant.Version + " (" + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + ")\n")
		os.Stdout.WriteString("tags: " + strings.Join(tags, ",") + "\n")
	},
}

func init() {
	command.Flags().StringVarP(&configPath, "config", "c", "config.json", "configuration file path")
	command.AddCommand(versionCommand)
}

func main() {
	err := command.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	configContent, err := os.ReadFile(configPath)
	if err != nil {
		return E.Cause(err, "read configuration file")
	}
	var options option.Options
	decoder := json.NewDecoder(json.NewCommentFilter(bytes.NewReader(configContent)))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&options)
	if err != nil {
		var syntaxError *json.SyntaxError
		if errors.As(err, &syntaxError) {
			prefix := string(configContent[:syntaxError.Offset])
			row := strings.Count(prefix, "\n") + 1
			column := len(prefix) - strings.LastIndex(prefix, "\n") - 1
			return E.Cause(E.Extend(syntaxError, "row ", row, ", column ", column), "decode configuration file")
		}
		return E.Cause(err, "decode configuration file")
	}
	ctx, cancel := context.WithCancel(context.Background())
	server, err := nextserver.New(ctx, options)
	if err != nil {
		cancel()
		return E.Cause(err, "create service")
	}
	err = server.Start()
	if err != nil {
		cancel()
		return E.Cause(err, "start service")
	}
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	<-osSignals
	cancel()
	closeCtx, closed := context.WithCancel(context.Background())
	go closeMonitor(closeCtx)
	err = server.Close()
	if err != nil {
		log.Error("close service: ", err)
	}
	closed()
	return nil
}

func closeMonitor(ctx context.Context) {
	// Long enough for the final traffic report.
	time.Sleep(constant.FinalPushTimeout + 5*time.Second)
	select {
	case <-ctx.Done():
		return
	default:
	}
	log.Fatal("next-server did not close!")
}
