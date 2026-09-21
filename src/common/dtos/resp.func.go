package dtos

import (
	"net/http"

	apperrors "github.com/better-go-auth/goauth/src/common/errors"
)


func BadReqM[T any](errorMessage string) GResp[T] {
	return GResp[T]{
		Status: http.StatusBadRequest,
		Code:   apperrors.BadRequest,
		Error:  errorMessage,
		Ok:     false,
	}
}

func BadReqC[T any](code apperrors.RespCode) GResp[T] {
	return GResp[T]{
		Status:  http.StatusBadRequest,
		Code:    code,
		Error:   code.Msg(),
		Message: code.Msg(),
	}
}

func InternalErrMS[T any](message string) GResp[T] {
	return GResp[T]{
		Status: http.StatusInternalServerError,
		Code:   apperrors.FAIL,
		Error:  message,
	}
}

func SuccessCreated[T any](item T, rowsAffected int64) GResp[T] {
	return GResp[T]{
		Status:       http.StatusCreated,
		Code:         apperrors.Success,
		Message:      "success",
		Body:         item,
		RowsAffected: rowsAffected,
	}
}

func SuccessOkCode[T any](item T, code apperrors.RespCode, rowsAffected int64) GResp[T] {
	return GResp[T]{
		Status:       http.StatusOK,
		Code:         code,
		Message:      code.Msg(),
		Body:         item,
		RowsAffected: rowsAffected,
	}
}
