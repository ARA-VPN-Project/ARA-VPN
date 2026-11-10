package service

import "os"

func osReadFile(p string) ([]byte, error) { return os.ReadFile(p) }
