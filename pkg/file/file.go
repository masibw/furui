package file

import "os"

func Exists(filepath string) (exist bool) {
	_, err := os.Stat(filepath)
	return err == nil
}
