// SYNTHETIC FIXTURE: hand-written test input for parse_go_mod().
// Not scanner evidence and not taken from a real project.
// 3 required modules: 1 direct, 2 marked // indirect.
module example.com/recon-dg/synthetic-demo

go 1.22

require github.com/gin-gonic/gin v1.9.1

require (
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/text v0.13.0 // indirect
)
