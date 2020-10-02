package clxc

import (
	// consider an alternative json parser
	// e.g https://github.com/buger/jsonparser
	//"github.com/pkg/json" // adds about 200k
	"encoding/json" // adds about 400k
	"os"
)

// TODO default spec path here

type InitSpec struct {
	SyncFifo string // path to syncfifo
	Message  string // message send to syncfifo

	AdditionalGids []int // must only be set when CAP_SETGID is enabled
	UserName       string
	Env            []string
	Args           []string
	Cwd            string
}

func (spec *InitSpec) ParseFile(specFilePath string) error {
	specFile, err := os.Open(specFilePath)
	if err != nil {
		return err
	}
	defer specFile.Close()
	return json.NewDecoder(specFile).Decode(&spec)
}

func (spec *InitSpec) WriteFile(specFilePath string) error {
	f, err := os.OpenFile(specFilePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0555)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(spec)
}
