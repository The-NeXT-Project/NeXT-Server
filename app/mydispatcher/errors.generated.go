package mydispatcher

import "github.com/v2fly/v2ray-core/v5/common/errors"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
