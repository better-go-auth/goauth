package util_test

import (
	"testing"

	"github.com/better-go-auth/goauth/src/common/util"
	"github.com/stretchr/testify/assert"
)

func TestGenerateRandomString(t *testing.T) {
	s1, err1 := util.GenerateRandomString(16)
	assert.NoError(t, err1)
	s2, err2 := util.GenerateRandomString(16)
	assert.NoError(t, err2)
	assert.Len(t, s1, 16)
	assert.Len(t, s2, 16)
	assert.NotEqual(t, s1, s2)
}

func TestArrayUtils(t *testing.T) {
	assert.True(t, util.ElementExists("apple", "banana", "apple", "cherry"))
	assert.False(t, util.ElementExists("orange", "banana", "apple", "cherry"))
}
