// Package model defines the database models and data structures used by the 3x-ui panel.
package model

import (
	"encoding/json"
	"fmt"

	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"gorm.io/gorm"
)

// Protocol represents the protocol type for Xray inbounds.
type Protocol string

// Protocol constants for different Xray inbound protocols
const (
	VMESS       Protocol = "vmess"
	VLESS       Protocol = "vless"
	Tunnel      Protocol = "tunnel"
	HTTP        Protocol = "http"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
	Mixed       Protocol = "mixed"
	WireGuard   Protocol = "wireguard"
)

// User represents a user account in the 3x-ui panel.
type User struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Inbound represents an Xray inbound configuration with traffic statistics and settings.
type Inbound struct {
	Id                   int                  `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`                                                    // Unique identifier
	UserId               int                  `json:"-"`                                                                                               // Associated user ID
	Up                   int64                `json:"up" form:"up"`                                                                                    // Upload traffic in bytes
	Down                 int64                `json:"down" form:"down"`                                                                                // Download traffic in bytes
	Total                int64                `json:"total" form:"total"`                                                                              // Total traffic limit in bytes
	AllTime              int64                `json:"allTime" form:"allTime" gorm:"default:0"`                                                         // All-time traffic usage
	Remark               string               `json:"remark" form:"remark"`                                                                            // Human-readable remark
	Enable               bool                 `json:"enable" form:"enable" gorm:"index:idx_enable_traffic_reset,priority:1"`                           // Whether the inbound is enabled
	ExpiryTime           int64                `json:"expiryTime" form:"expiryTime"`                                                                    // Expiration timestamp
	TrafficReset         string               `json:"trafficReset" form:"trafficReset" gorm:"default:never;index:idx_enable_traffic_reset,priority:2"` // Traffic reset schedule
	LastTrafficResetTime int64                `json:"lastTrafficResetTime" form:"lastTrafficResetTime" gorm:"default:0"`                               // Last traffic reset timestamp
	ClientStats          []xray.ClientTraffic `gorm:"foreignKey:InboundId;references:Id" json:"clientStats" form:"clientStats"`                        // Client traffic statistics

	// Xray configuration fields
	Listen         string   `json:"listen" form:"listen"`
	Port           int      `json:"port" form:"port"`
	Protocol       Protocol `json:"protocol" form:"protocol"`
	Settings       string   `json:"settings" form:"settings"`
	StreamSettings string   `json:"streamSettings" form:"streamSettings"`
	Tag            string   `json:"tag" form:"tag" gorm:"unique"`
	Sniffing       string   `json:"sniffing" form:"sniffing"`

	// Normalized runtime columns (mirrors legacy JSON fields)
	Decryption             string `json:"decryption" form:"decryption"`
	Encryption             string `json:"encryption" form:"encryption"`
	Network                string `json:"network" form:"network"`
	Security               string `json:"security" form:"security"`
	ExternalProxy          string `json:"externalProxy" form:"externalProxy"`
	RealityShow            bool   `json:"realityShow" form:"realityShow"`
	RealityXver            int    `json:"realityXver" form:"realityXver"`
	RealityTarget          string `json:"realityTarget" form:"realityTarget"`
	RealityServerNames     string `json:"realityServerNames" form:"realityServerNames"`
	RealityPrivateKey      string `json:"realityPrivateKey" form:"realityPrivateKey"`
	RealityMinClientVer    string `json:"realityMinClientVer" form:"realityMinClientVer"`
	RealityMaxClientVer    string `json:"realityMaxClientVer" form:"realityMaxClientVer"`
	RealityMaxTimediff     int    `json:"realityMaxTimediff" form:"realityMaxTimediff"`
	RealityShortIds        string `json:"realityShortIds" form:"realityShortIds"`
	RealityMldsa65Seed     string `json:"realityMldsa65Seed" form:"realityMldsa65Seed"`
	RealityPublicKey       string `json:"realityPublicKey" form:"realityPublicKey"`
	RealityFingerprint     string `json:"realityFingerprint" form:"realityFingerprint"`
	RealityServerName      string `json:"realityServerName" form:"realityServerName"`
	RealitySpiderX         string `json:"realitySpiderX" form:"realitySpiderX"`
	RealityMldsa65Verify   string `json:"realityMldsa65Verify" form:"realityMldsa65Verify"`
	TCPAcceptProxyProtocol bool   `json:"tcpAcceptProxyProtocol" form:"tcpAcceptProxyProtocol"`
	TCPHeaderType          string `json:"tcpHeaderType" form:"tcpHeaderType"`
	SniffingEnabled        bool   `json:"sniffingEnabled" form:"sniffingEnabled"`
	SniffingDestOverride   string `json:"sniffingDestOverride" form:"sniffingDestOverride"`
	SniffingMetadataOnly   bool   `json:"sniffingMetadataOnly" form:"sniffingMetadataOnly"`
	SniffingRouteOnly      bool   `json:"sniffingRouteOnly" form:"sniffingRouteOnly"`

	Clients []InboundClient `json:"clients,omitempty" gorm:"foreignKey:InboundId;references:Id"`
}

// InboundClient stores normalized inbound clients instead of embedding them in inbounds.settings JSON.
type InboundClient struct {
	Id         int    `json:"-" gorm:"primaryKey;autoIncrement"`
	InboundId  int    `json:"inboundId" gorm:"index"`
	ClientID   string `json:"id" gorm:"column:client_id;index"`
	Security   string `json:"security"`
	Password   string `json:"password"`
	Flow       string `json:"flow"`
	Email      string `json:"email" gorm:"index"`
	LimitIP    int    `json:"limitIp"`
	TotalGB    int64  `json:"totalGB"`
	ExpiryTime int64  `json:"expiryTime"`
	Enable     bool   `json:"enable"`
	TgID       int64  `json:"tgId"`
	SubID      string `json:"subId"`
	Comment    string `json:"comment"`
	Reset      int    `json:"reset"`
	CreatedAt  int64  `json:"created_at,omitempty"`
	UpdatedAt  int64  `json:"updated_at,omitempty"`
}

func (InboundClient) TableName() string {
	return "clients"
}

func (i *Inbound) BeforeSave(tx *gorm.DB) error {
	return i.syncNormalizedFieldsFromJSON()
}

func (i *Inbound) AfterFind(tx *gorm.DB) error {
	if err := tx.Where("inbound_id = ?", i.Id).Find(&i.Clients).Error; err != nil {
		return err
	}
	if len(i.Clients) == 0 && i.Decryption == "" && i.Encryption == "" && i.Network == "" && i.Security == "" {
		return i.syncNormalizedFieldsFromJSON()
	}
	return i.syncJSONFromNormalizedFields()
}

func (i *Inbound) AfterSave(tx *gorm.DB) error {
	if i.Id == 0 {
		return nil
	}
	if err := tx.Where("inbound_id = ?", i.Id).Delete(&InboundClient{}).Error; err != nil {
		return err
	}
	if len(i.Clients) == 0 {
		return nil
	}
	for idx := range i.Clients {
		i.Clients[idx].InboundId = i.Id
	}
	return tx.Create(&i.Clients).Error
}

func (i *Inbound) syncNormalizedFieldsFromJSON() error {
	type inboundSettings struct {
		Clients    []Client `json:"clients"`
		Decryption string   `json:"decryption"`
		Encryption string   `json:"encryption"`
	}
	if i.Settings != "" {
		var settings inboundSettings
		if err := json.Unmarshal([]byte(i.Settings), &settings); err != nil {
			return err
		}
		i.Decryption = settings.Decryption
		i.Encryption = settings.Encryption
		i.Clients = make([]InboundClient, 0, len(settings.Clients))
		for _, client := range settings.Clients {
			i.Clients = append(i.Clients, InboundClient{InboundId: i.Id, ClientID: client.ID, Security: client.Security, Password: client.Password, Flow: client.Flow, Email: client.Email, LimitIP: client.LimitIP, TotalGB: client.TotalGB, ExpiryTime: client.ExpiryTime, Enable: client.Enable, TgID: client.TgID, SubID: client.SubID, Comment: client.Comment, Reset: client.Reset, CreatedAt: client.CreatedAt, UpdatedAt: client.UpdatedAt})
		}
	}
	if i.StreamSettings != "" {
		var stream map[string]any
		if err := json.Unmarshal([]byte(i.StreamSettings), &stream); err != nil {
			return err
		}
		i.Network = stringVal(stream["network"])
		i.Security = stringVal(stream["security"])
		i.ExternalProxy = mustJSON(stream["externalProxy"])
		if reality, ok := stream["realitySettings"].(map[string]any); ok {
			i.RealityShow = boolVal(reality["show"])
			i.RealityXver = intVal(reality["xver"])
			i.RealityTarget = stringVal(reality["target"])
			i.RealityServerNames = mustJSON(reality["serverNames"])
			i.RealityPrivateKey = stringVal(reality["privateKey"])
			i.RealityMinClientVer = stringVal(reality["minClientVer"])
			i.RealityMaxClientVer = stringVal(reality["maxClientVer"])
			i.RealityMaxTimediff = intVal(reality["maxTimediff"])
			i.RealityShortIds = mustJSON(reality["shortIds"])
			i.RealityMldsa65Seed = stringVal(reality["mldsa65Seed"])
			if settings, ok := reality["settings"].(map[string]any); ok {
				i.RealityPublicKey = stringVal(settings["publicKey"])
				i.RealityFingerprint = stringVal(settings["fingerprint"])
				i.RealityServerName = stringVal(settings["serverName"])
				i.RealitySpiderX = stringVal(settings["spiderX"])
				i.RealityMldsa65Verify = stringVal(settings["mldsa65Verify"])
			}
		}
		if tcp, ok := stream["tcpSettings"].(map[string]any); ok {
			i.TCPAcceptProxyProtocol = boolVal(tcp["acceptProxyProtocol"])
			if header, ok := tcp["header"].(map[string]any); ok {
				i.TCPHeaderType = stringVal(header["type"])
			}
		}
	}
	if i.Sniffing != "" {
		var sniffing map[string]any
		if err := json.Unmarshal([]byte(i.Sniffing), &sniffing); err != nil {
			return err
		}
		i.SniffingEnabled = boolVal(sniffing["enabled"])
		i.SniffingDestOverride = mustJSON(sniffing["destOverride"])
		i.SniffingMetadataOnly = boolVal(sniffing["metadataOnly"])
		i.SniffingRouteOnly = boolVal(sniffing["routeOnly"])
	}
	return nil
}

func (i *Inbound) syncJSONFromNormalizedFields() error {
	clients := make([]Client, 0, len(i.Clients))
	for _, c := range i.Clients {
		clients = append(clients, Client{ID: c.ClientID, Security: c.Security, Password: c.Password, Flow: c.Flow, Email: c.Email, LimitIP: c.LimitIP, TotalGB: c.TotalGB, ExpiryTime: c.ExpiryTime, Enable: c.Enable, TgID: c.TgID, SubID: c.SubID, Comment: c.Comment, Reset: c.Reset, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt})
	}
	settingsJSON, err := json.Marshal(map[string]any{"clients": clients, "decryption": i.Decryption, "encryption": i.Encryption})
	if err != nil {
		return err
	}
	streamJSON, err := json.Marshal(map[string]any{
		"network":       i.Network,
		"security":      i.Security,
		"externalProxy": mustJSONArray(i.ExternalProxy),
		"realitySettings": map[string]any{
			"show":         i.RealityShow,
			"xver":         i.RealityXver,
			"target":       i.RealityTarget,
			"serverNames":  mustJSONArray(i.RealityServerNames),
			"privateKey":   i.RealityPrivateKey,
			"minClientVer": i.RealityMinClientVer,
			"maxClientVer": i.RealityMaxClientVer,
			"maxTimediff":  i.RealityMaxTimediff,
			"shortIds":     mustJSONArray(i.RealityShortIds),
			"mldsa65Seed":  i.RealityMldsa65Seed,
			"settings": map[string]any{
				"publicKey":     i.RealityPublicKey,
				"fingerprint":   i.RealityFingerprint,
				"serverName":    i.RealityServerName,
				"spiderX":       i.RealitySpiderX,
				"mldsa65Verify": i.RealityMldsa65Verify,
			},
		},
		"tcpSettings": map[string]any{"acceptProxyProtocol": i.TCPAcceptProxyProtocol, "header": map[string]any{"type": i.TCPHeaderType}},
	})
	if err != nil {
		return err
	}
	sniffingJSON, err := json.Marshal(map[string]any{"enabled": i.SniffingEnabled, "destOverride": mustJSONArray(i.SniffingDestOverride), "metadataOnly": i.SniffingMetadataOnly, "routeOnly": i.SniffingRouteOnly})
	if err != nil {
		return err
	}
	i.Settings = string(settingsJSON)
	i.StreamSettings = string(streamJSON)
	i.Sniffing = string(sniffingJSON)
	return nil
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func mustJSONArray(raw string) any {
	if raw == "" {
		return []any{}
	}
	var out any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return []any{}
	}
	return out
}
func stringVal(v any) string { s, _ := v.(string); return s }
func boolVal(v any) bool     { b, _ := v.(bool); return b }
func intVal(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

// OutboundTraffics tracks traffic statistics for Xray outbound connections.
type OutboundTraffics struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Tag   string `json:"tag" form:"tag" gorm:"unique"`
	Up    int64  `json:"up" form:"up" gorm:"default:0"`
	Down  int64  `json:"down" form:"down" gorm:"default:0"`
	Total int64  `json:"total" form:"total" gorm:"default:0"`
}

// InboundClientIps stores IP addresses associated with inbound clients for access control.
type InboundClientIps struct {
	Id          int    `json:"id" gorm:"primaryKey;autoIncrement"`
	ClientEmail string `json:"clientEmail" form:"clientEmail" gorm:"unique"`
	Ips         string `json:"ips" form:"ips"`
}

// HistoryOfSeeders tracks which database seeders have been executed to prevent re-running.
type HistoryOfSeeders struct {
	Id         int    `json:"id" gorm:"primaryKey;autoIncrement"`
	SeederName string `json:"seederName"`
}

// GenXrayInboundConfig generates an Xray inbound configuration from the Inbound model.
func (i *Inbound) GenXrayInboundConfig() *xray.InboundConfig {
	listen := i.Listen
	// Default to 0.0.0.0 (all interfaces) when listen is empty
	// This ensures proper dual-stack IPv4/IPv6 binding in systems where bindv6only=0
	if listen == "" {
		listen = "0.0.0.0"
	}
	listen = fmt.Sprintf("\"%v\"", listen)
	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(listen),
		Port:           i.Port,
		Protocol:       string(i.Protocol),
		Settings:       json_util.RawMessage(i.Settings),
		StreamSettings: json_util.RawMessage(i.StreamSettings),
		Tag:            i.Tag,
		Sniffing:       json_util.RawMessage(i.Sniffing),
	}
}

// Setting stores key-value configuration settings for the 3x-ui panel.
type Setting struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Key   string `json:"key" form:"key"`
	Value string `json:"value" form:"value"`
}

// Client represents a client configuration for Xray inbounds with traffic limits and settings.
type Client struct {
	ID         string `json:"id"`                           // Unique client identifier
	Security   string `json:"security"`                     // Security method (e.g., "auto", "aes-128-gcm")
	Password   string `json:"password"`                     // Client password
	Flow       string `json:"flow"`                         // Flow control (XTLS)
	Email      string `json:"email"`                        // Client email identifier
	LimitIP    int    `json:"limitIp"`                      // IP limit for this client
	TotalGB    int64  `json:"totalGB" form:"totalGB"`       // Total traffic limit in GB
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"` // Expiration timestamp
	Enable     bool   `json:"enable" form:"enable"`         // Whether the client is enabled
	TgID       int64  `json:"tgId" form:"tgId"`             // Telegram user ID for notifications
	SubID      string `json:"subId" form:"subId"`           // Subscription identifier
	Comment    string `json:"comment" form:"comment"`       // Client comment
	Reset      int    `json:"reset" form:"reset"`           // Reset period in days
	CreatedAt  int64  `json:"created_at,omitempty"`         // Creation timestamp
	UpdatedAt  int64  `json:"updated_at,omitempty"`         // Last update timestamp
}
