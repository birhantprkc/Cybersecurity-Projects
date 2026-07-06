// ©AngelaMos | 2026
// tui.go

package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/nadezhda/internal/rank"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
	"github.com/CarterPerez-dev/nadezhda/internal/tui"
)

var tuiSince string

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Browse aggregated news in an interactive terminal UI",
	RunE:  runTUI,
}

func init() {
	tuiCmd.Flags().StringVar(&tuiSince, "since", "", "only clusters active within this window (e.g. 24h, 168h)")
	rootCmd.AddCommand(tuiCmd)
}

func runTUI(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	now := time.Now()
	var since int64
	if tuiSince != "" {
		d, err := time.ParseDuration(tuiSince)
		if err != nil {
			return fmt.Errorf("invalid --since %q: %w", tuiSince, err)
		}
		since = now.Add(-d).Unix()
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	loader := func() (tui.Data, error) {
		clusters, err := st.DigestClusters(since)
		if err != nil {
			return tui.Data{}, err
		}
		scored := rank.Rank(clusters, cfg.Rank, cfg.Watchlist, now)
		detail := make(map[string]store.CVE)
		for _, s := range scored {
			for _, v := range s.Cluster.CVEs {
				if _, ok := detail[v.ID]; ok {
					continue
				}
				full, err := st.GetCVE(v.ID)
				if err != nil {
					continue
				}
				detail[v.ID] = full
			}
		}
		return tui.Data{Scored: scored, CVEDetail: detail}, nil
	}

	return tui.Run(loader)
}
