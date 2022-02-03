package process

type pidStack struct {
	top  *pidStackElement
	size int
}

type pidStackElement struct {
	pid  int
	next *pidStackElement
}

func (s *pidStack) Len() int {
	return s.size
}

func (s *pidStack) Push(pids ...int) {
	for i := len(pids) - 1; i >= 0; i-- {
		s.top = &pidStackElement{pids[i], s.top}
		s.size++
	}
}

func (s *pidStack) Pop() (pid int) {
	if s.size > 0 {
		pid, s.top = s.top.pid, s.top.next
		s.size--
		return
	}
	return -1
}
