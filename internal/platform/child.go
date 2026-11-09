package platform

import (
	"errors"
	"os/exec"
)

// Коды выхода процесса-окна (--window). Нужны родителю, чтобы понять, почему окно не открылось.
const (
	ExitNoRuntime = 3 // на ПК нет WebView2
	ExitNoWindow  = 4 // окно создать не удалось
)

// Child — дочерний процесс с окном интерфейса. Окно живёт отдельным процессом: если встроенный
// браузер (WebView2) упадёт или не запустится, это не заденет сам обход.
type Child struct {
	PID  uint32
	cmd  *exec.Cmd
	done chan struct{}
	code int
}

func startChild(cmd *exec.Cmd) (*Child, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &Child{PID: uint32(cmd.Process.Pid), cmd: cmd, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		var ee *exec.ExitError
		switch {
		case err == nil:
			c.code = 0
		case errors.As(err, &ee):
			c.code = ee.ExitCode()
		default:
			c.code = -1
		}
		close(c.done)
	}()
	return c, nil
}

// Alive сообщает, работает ли окно.
func (c *Child) Alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// Wait ждёт закрытия окна и возвращает код выхода.
func (c *Child) Wait() int {
	<-c.done
	return c.code
}

// Kill закрывает окно.
func (c *Child) Kill() {
	if c.Alive() {
		_ = c.cmd.Process.Kill()
	}
}
