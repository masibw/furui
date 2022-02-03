package loader

import (
	"os"
	"testing"

	bpf "github.com/iovisor/gobpf/bcc"
)

// readFile opens a file at the specified path and returns []bytes
func readFile(t *testing.T, path string) (p []byte) {
	t.Helper()
	var err error
	p, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to open file path: %s, err: %s", path, err)
		return nil
	}
	return
}

func TestEbpfLoader_LoadBindProg(t *testing.T) {
	type fields struct {
		bindProg    []byte
		connectProg []byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantM   *bpf.Module
		wantErr bool
	}{
		{
			name: "Successfully load and attach the bind program.",
			fields: fields{
				bindProg:    readFile(t, "../../usecase/ebpf/bind.c"),
				connectProg: readFile(t, "../../usecase/ebpf/connect.c"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &EbpfLoader{
				bindProg:    tt.fields.bindProg,
				connectProg: tt.fields.connectProg,
			}
			gotM, err := l.LoadBindProg()
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadBindProg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotM.NumOpenKprobes() < 1 {
				t.Errorf("failed to attach bind program")
				return
			}
		})
	}
}
