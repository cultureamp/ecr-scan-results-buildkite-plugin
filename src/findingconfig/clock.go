package findingconfig

import "time"

type SystemClock func() time.Time

func (c SystemClock) UtcNow() time.Time {
	return c()
}

func DefaultSystemClock() SystemClock {
	return SystemClock(func() time.Time {
		return time.Now().UTC()
	})
}
