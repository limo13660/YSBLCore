package updater

import (
	"context"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// GeoUpdateHook is intentionally optional. Embedding clients may subscribe to
// progress events without coupling the core updater to a UI implementation.
var GeoUpdateHook func(geoType string, updating bool, skipped bool, updateErr error)

func sendGeoUpdateStatus(geoType string, updating bool, skipped bool, updateErr error) {
	if GeoUpdateHook != nil {
		GeoUpdateHook(geoType, updating, skipped, updateErr)
	}
}

var geoUpdater = struct {
	sync.Mutex
	cancel context.CancelFunc
}{}

// StopGeoUpdater cancels the previous background updater, if any. It is safe
// to call during shutdown and when auto-update is disabled by a config patch.
func StopGeoUpdater() {
	geoUpdater.Lock()
	if geoUpdater.cancel != nil {
		geoUpdater.cancel()
		geoUpdater.cancel = nil
	}
	geoUpdater.Unlock()
}

// RegisterGeoUpdaterWithCancel replaces a running updater instead of creating
// an additional ticker on every configuration update.
func RegisterGeoUpdaterWithCancel() {
	StopGeoUpdater()
	if updateInterval <= 0 {
		log.Errorln("[GEO] Invalid update interval: %d", updateInterval)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	geoUpdater.Lock()
	geoUpdater.cancel = cancel
	geoUpdater.Unlock()

	go func() {
		ticker := time.NewTicker(time.Duration(updateInterval) * time.Hour)
		defer ticker.Stop()

		lastUpdate, err := getUpdateTime()
		if err != nil {
			log.Errorln("[GEO] Get GEO database update time error: %s", err.Error())
			return
		}
		if lastUpdate.Add(time.Duration(updateInterval) * time.Hour).Before(time.Now()) {
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := UpdateGeoDatabases(); err != nil {
					log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
				}
			}
		}
	}()
}
