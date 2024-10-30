package models

import "errors"

var (
	ErrFileAlreadyExists        = errors.New("file already exists")
	ErrFileDoesNotExist         = errors.New("file does not exist")
	ErrNoDataUnits              = errors.New("no data units in file")
	ErrDataUnitNotFound         = errors.New("data unit not found in file")
	ErrDataUnitIsAlreadyPresent = errors.New("data unit with the name is already present in file")
)
