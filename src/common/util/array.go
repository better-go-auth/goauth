package util

import "slices"

func ElementExists[T comparable](element T, arr ...T) bool {
	return slices.Contains(arr, element)
}
