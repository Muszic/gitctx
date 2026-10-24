package managedkey

import (
	"errors"
	"os"
)

func checkOwner(os.FileInfo) error {
	return errors.New("native managed keys require a supported Unix password vault")
}
