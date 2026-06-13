package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	StateStopped  = 0
	StateStarting = 10
	StateRunning  = 20
	StateStopping = 40
	StateExited   = 100
	StateFatal    = 200
)

type ProcessInfo struct {
	Name      string `json:"name"`
	State     int    `json:"state"`
	StateName string `json:"statename"`
	Raw       string `json:"raw"`
}

type Client struct {
	socketPath string
	username   string
	password   string
}

func New(socketPath, username, password string) *Client {
	return &Client{
		socketPath: socketPath,
		username:   username,
		password:   password,
	}
}

func (c *Client) GetState(ctx context.Context) error {
	if c.socketPath == "" {
		return errors.New("supervisord socket path is empty")
	}
	_, err := c.run(ctx, "status")
	return err
}

func (c *Client) StartProcess(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("process name is empty")
	}
	_, err := c.run(ctx, "start", name)
	return err
}

func (c *Client) StopProcess(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("process name is empty")
	}
	_, err := c.run(ctx, "stop", name)
	return err
}

func (c *Client) GetProcessInfo(ctx context.Context, name string) (ProcessInfo, error) {
	if name == "" {
		return ProcessInfo{}, errors.New("process name is empty")
	}
	output, err := c.run(ctx, "status", name)
	if err != nil && output == "" {
		return ProcessInfo{}, err
	}

	fields := strings.Fields(output)
	if len(fields) < 2 {
		return ProcessInfo{
			Name:      name,
			State:     StateStopped,
			StateName: "UNKNOWN",
			Raw:       strings.TrimSpace(output),
		}, err
	}

	stateName := strings.ToUpper(fields[1])
	return ProcessInfo{
		Name:      fields[0],
		StateName: stateName,
		State:     mapState(stateName),
		Raw:       strings.TrimSpace(output),
	}, err
}

func (c *Client) run(ctx context.Context, args ...string) (string, error) {
	commandArgs := []string{}
	if c.socketPath != "" {
		commandArgs = append(commandArgs, "-s", "unix://"+c.socketPath)
	}
	if c.username != "" {
		commandArgs = append(commandArgs, "-u", c.username)
	}
	if c.password != "" {
		commandArgs = append(commandArgs, "-p", c.password)
	}
	commandArgs = append(commandArgs, args...)

	cmd := exec.CommandContext(ctx, "supervisorctl", commandArgs...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	output := strings.TrimSpace(stdout.String())
	if output == "" {
		output = strings.TrimSpace(stderr.String())
	}
	if err != nil {
		return output, fmt.Errorf("supervisorctl %s failed: %w (%s)", strings.Join(args, " "), err, output)
	}
	return output, nil
}

func mapState(state string) int {
	switch state {
	case "RUNNING":
		return StateRunning
	case "STARTING":
		return StateStarting
	case "STOPPING":
		return StateStopping
	case "EXITED", "STOPPED":
		return StateStopped
	case "FATAL", "BACKOFF":
		return StateFatal
	default:
		return StateStopped
	}
}
