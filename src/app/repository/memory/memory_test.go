package memory_test

import (
	"testing"

	"github.com/better-go-auth/goauth/src/app/repository/memory"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/app/repository/repotest"
)

func TestContract(t *testing.T) {
	repotest.Run(t, func(t *testing.T) repo_interfaces.IAuthRepos { return memory.New() })
}
