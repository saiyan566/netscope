package main

import "fmt"

type exitError struct {
	Code int
	Err  error
}

func (e exitError) Error() string {
	return e.Err.Error()
}

type safetyMode string

const (
	safetyPassive safetyMode = "PASSIVE"
	safetyActive  safetyMode = "ACTIVE"
	safetyLocal   safetyMode = "LOCAL"
)

type safetyDecision struct {
	Mode        safetyMode
	RequiresAck bool
	Reason      string
}

func evaluateSafety(request engineRequest) safetyDecision {
	switch request.Command {
	case "discover":
		return activeDecision("live host discovery sends TCP liveness probes to target infrastructure")
	case "scan":
		return activeDecision("scan sends TCP/UDP probes to target infrastructure")
	case "vuln":
		if request.InputFile != "" && len(request.Targets) == 0 && request.TargetFile == "" {
			return localDecision("vulnerability analysis reads prior local JSONL input")
		}
		return activeDecision("live vulnerability checks inspect target infrastructure")
	case "recon":
		if request.LiveIPs {
			return activeDecision("recon --live-ips sends TCP liveness probes to CIDR candidates")
		}
		return passiveDecision("passive recon uses public sources, public DNS, archive indexes, certificate transparency, and RDAP")
	case "dns-audit":
		return passiveDecision("DNS posture audit uses public DNS resolver data only")
	case "diff", "report":
		return localDecision("command reads local result files")
	default:
		return localDecision("command does not have active target probes")
	}
}

func activeDecision(reason string) safetyDecision {
	return safetyDecision{Mode: safetyActive, RequiresAck: true, Reason: reason}
}

func passiveDecision(reason string) safetyDecision {
	return safetyDecision{Mode: safetyPassive, RequiresAck: false, Reason: reason}
}

func localDecision(reason string) safetyDecision {
	return safetyDecision{Mode: safetyLocal, RequiresAck: false, Reason: reason}
}

func enforceSafety(opts cliOptions) error {
	decision := evaluateSafety(opts.request)
	if decision.RequiresAck && !opts.ackAuthorized {
		return fmt.Errorf("%s mode requires --ack-authorized: %s", decision.Mode, decision.Reason)
	}
	return nil
}
