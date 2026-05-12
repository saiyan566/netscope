package main

import (
	"flag"
	"fmt"
)

type scanProfile struct {
	Name          string
	Description   string
	TCP           bool
	UDP           bool
	Ports         string
	TopPorts      int
	TopUDP        int
	DiscoverHosts bool
	SSHAudit      bool
	ServiceDetect bool
	HTTPAudit     bool
	TLSAudit      bool
	TimeoutMS     int
	Concurrency   int
	MemoryMB      int
}

var scanProfiles = []scanProfile{
	{
		Name:        "quick",
		Description: "fast TCP scan of the most common ports with low resource use",
		TCP:         true,
		TopPorts:    25,
		TimeoutMS:   700,
		Concurrency: 128,
		MemoryMB:    96,
	},
	{
		Name:          "standard",
		Description:   "balanced TCP scan with curated UDP and SSH posture checks",
		TCP:           true,
		UDP:           true,
		TopPorts:      100,
		TopUDP:        20,
		SSHAudit:      true,
		ServiceDetect: true,
		HTTPAudit:     true,
		TimeoutMS:     900,
		Concurrency:   256,
		MemoryMB:      150,
	},
	{
		Name:          "deep",
		Description:   "broader authorized scan with more TCP and UDP coverage",
		TCP:           true,
		UDP:           true,
		TopPorts:      1000,
		TopUDP:        50,
		SSHAudit:      true,
		ServiceDetect: true,
		HTTPAudit:     true,
		TLSAudit:      true,
		TimeoutMS:     1500,
		Concurrency:   256,
		MemoryMB:      256,
	},
	{
		Name:          "external",
		Description:   "internet-facing defensive check of common exposed services",
		TCP:           true,
		Ports:         "22,25,53,80,110,143,443,465,587,993,995,1433,1521,3306,3389,5432,6379,8080,8443",
		SSHAudit:      true,
		ServiceDetect: true,
		HTTPAudit:     true,
		TLSAudit:      true,
		TimeoutMS:     1200,
		Concurrency:   192,
		MemoryMB:      150,
	},
	{
		Name:          "internal",
		Description:   "private-network-friendly scan with host discovery and curated UDP",
		TCP:           true,
		UDP:           true,
		TopPorts:      200,
		TopUDP:        30,
		DiscoverHosts: true,
		SSHAudit:      true,
		ServiceDetect: true,
		HTTPAudit:     true,
		TimeoutMS:     900,
		Concurrency:   256,
		MemoryMB:      150,
	},
}

func scanProfileByName(name string) *scanProfile {
	for i := range scanProfiles {
		if scanProfiles[i].Name == name {
			return &scanProfiles[i]
		}
	}
	return nil
}

func applyScanProfile(opts *cliOptions, fs *flag.FlagSet, name string) error {
	profile := scanProfileByName(name)
	if profile == nil {
		return fmt.Errorf("unknown scan profile %q; expected quick, standard, deep, external, or internal", name)
	}

	if profile.TCP && !flagWasSet(fs, "tcp") {
		opts.request.TCP = true
	}
	if profile.UDP && !flagWasSet(fs, "udp") {
		opts.request.UDP = true
	}
	if profile.Ports != "" && !flagWasSet(fs, "ports") {
		opts.request.Ports = profile.Ports
	}
	if profile.TopPorts > 0 && !flagWasSet(fs, "top-ports") {
		opts.request.TopPorts = profile.TopPorts
	}
	if profile.TopUDP > 0 && !flagWasSet(fs, "top-udp") {
		opts.request.TopUDP = profile.TopUDP
	}
	if profile.DiscoverHosts && !flagWasSet(fs, "discover-hosts") && !flagWasSet(fs, "skip-host-discovery") {
		opts.request.DiscoverHosts = true
	}
	if profile.SSHAudit && !flagWasSet(fs, "ssh-audit") {
		opts.request.SSHAudit = true
	}
	if profile.ServiceDetect && !flagWasSet(fs, "service-detect") {
		opts.request.ServiceDetect = true
	}
	if profile.HTTPAudit && !flagWasSet(fs, "http-audit") {
		opts.request.HTTPAudit = true
	}
	if profile.TLSAudit && !flagWasSet(fs, "tls-audit") {
		opts.request.TLSAudit = true
	}
	if profile.TimeoutMS > 0 && !flagWasSet(fs, "timeout-ms") {
		opts.request.TimeoutMS = profile.TimeoutMS
	}
	if profile.Concurrency > 0 && !flagWasSet(fs, "concurrency") {
		opts.request.Concurrency = profile.Concurrency
	}
	if profile.MemoryMB > 0 && !flagWasSet(fs, "memory-budget-mb") {
		opts.request.MemoryBudgetMB = profile.MemoryMB
	}
	return nil
}
