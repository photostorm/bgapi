package bgapi

import "errors"

const (
	gapFuncNone     = iota
	gapFuncScanning = iota
)

/*
   dsef get_ad_type_string(self, type_ord):
       return {
           0x01: "BLE_GAP_AD_TYPE_FLAGS",
           0x02: "BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_MORE_AVAILABLE",
           0x03: "BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_COMPLETE",
           0x04: "BLE_GAP_AD_TYPE_32BIT_SERVICE_UUID_MORE_AVAILABLE",
           0x05: "BLE_GAP_AD_TYPE_32BIT_SERVICE_UUID_COMPLETE",
           0x06: "BLE_GAP_AD_TYPE_128BIT_SERVICE_UUID_MORE_AVAILABLE",
           0x07: "BLE_GAP_AD_TYPE_128BIT_SERVICE_UUID_COMPLETE",
           0x08: "BLE_GAP_AD_TYPE_SHORT_LOCAL_NAME",
           0x09: "BLE_GAP_AD_TYPE_COMPLETE_LOCAL_NAME",
           0x0A: "BLE_GAP_AD_TYPE_TX_POWER_LEVEL",
           0x0D: "BLE_GAP_AD_TYPE_CLASS_OF_DEVICE",
           0x0E: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_HASH_C",
           0x0F: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_RANDOMIZER_R",
           0x10: "BLE_GAP_AD_TYPE_SECURITY_MANAGER_TK_VALUE",
           0x11: "BLE_GAP_AD_TYPE_SECURITY_MANAGER_OOB_FLAGS",
           0x12: "BLE_GAP_AD_TYPE_SLAVE_CONNECTION_INTERVAL_RANGE",
           0x14: "BLE_GAP_AD_TYPE_SOLICITED_SERVICE_UUIDS_16BIT",
           0x15: "BLE_GAP_AD_TYPE_SOLICITED_SERVICE_UUIDS_128BIT",
           0x16: "BLE_GAP_AD_TYPE_SERVICE_DATA",
           0x17: "BLE_GAP_AD_TYPE_PUBLIC_TARGET_ADDRESS",
           0x18: "BLE_GAP_AD_TYPE_RANDOM_TARGET_ADDRESS",
           0x19: "BLE_GAP_AD_TYPE_APPEARANCE",
           0x1A: "BLE_GAP_AD_TYPE_ADVERTISING_INTERVAL",
           0x1B: "BLE_GAP_AD_TYPE_LE_BLUETOOTH_DEVICE_ADDRESS",
           0x1C: "BLE_GAP_AD_TYPE_LE_ROLE",
           0x1D: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_HASH_C256",
           0x1E: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_RANDOMIZER_R256",
           0x20: "BLE_GAP_AD_TYPE_SERVICE_DATA_32BIT_UUID",
           0x21: "BLE_GAP_AD_TYPE_SERVICE_DATA_128BIT_UUID",
           0x3D: "BLE_GAP_AD_TYPE_3D_INFORMATION_DATA",
           0xFF: "BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA"
       }[type_ord]
*/

/*
def parse_advertisement_data(self):
    remaining = self.data
    while len(remaining) > 0:
        length, = struct.unpack('B', remaining[:1])
        gap_data = remaining[1:length+1]

        adv_seg={}
        adv_seg_type, = struct.unpack('B', gap_data[:1])
        adv_seg["Type"] = self.get_ad_type_string(adv_seg_type)
        adv_seg["Data"] = gap_data[1:]
        self.adv_payload.append( adv_seg)
        #print("GAP Data: %s" % ("".join(["\\x%02x" % ord(i) for i in gap_data])))
        remaining = remaining[length+1:]

        if adv_seg_type == 0x1:  # Flags
            pass
        elif adv_seg_type == 0x02 or adv_seg_type == 0x03:  # Incomplete/Complete list of 16-bit UUIDs
            for i in range(1, len(gap_data) - 1, 2):
                self.services += [gap_data[i:i+2]]
        elif adv_seg_type == 0x04 or adv_seg_type == 0x05:  # Incomplete list of 32-bit UUIDs
            for i in range(1, len(gap_data) - 3, 4):
                self.services += [gap_data[i:i+4]]
        elif adv_seg_type == 0x06 or adv_seg_type == 0x07:  # Incomplete list of 128-bit UUIDs
            for i in range(1, len(gap_data) - 15, 16):
                self.services += [gap_data[i:i+16]]
*/

type apiDelegate struct {
	central *Central
}

// Central a base class that implements the central role
type Central struct {
	// NOTE: using a dedicated apiDelegate (as oposed to making the Central its own
	// apiDelegate) limits the scope of these methods
	apiDelegate      *apiDelegate
	api              *API
	gapFunc          int
	knownPeripherals map[string]*GapScanRespone
}

// AdvertisementData parsed advertisement data
type AdvertisementData map[byte][]byte

// ServiceUUIDs BLE variable length UUID list associated with a given service
type ServiceUUIDs [][]byte

func (c *Central) gapTake(gapFunc int) error {
	var err error
	if c.gapFunc == gapFuncNone {
		c.gapFunc = gapFunc
	} else {
		err = errors.New("GAP service already in use by another function")
	}
	return err
}

func (c *Central) gapGive(gapFunc int) error {
	var err error
	if c.gapFunc != gapFunc {
		err = errors.New("Attempt to release a GAP function not in use")
	} else {
		c.gapFunc = gapFuncNone
	}

	return err
}

// StartScanning start the scanning process
func (c *Central) StartScanning(mode byte) error {
	var err error
	if err = c.gapTake(gapFuncScanning); err == nil {
		c.api.GapDiscover(mode)
	}
	return err
}

// StopScanning stop the scanning function
func (c *Central) StopScanning() error {
	var err error
	if err = c.gapGive(gapFuncScanning); err == nil {
		c.api.GapEndProcedure()
	}

	return err
}

// ParseGapScanResponse parse a scan response
func ParseGapScanResponse(adv *GapScanRespone) *AdvertisementData {
	var cur int
	var result = AdvertisementData{}

	total := len(adv.Data)
	for (cur + 1) < total {
		// parse atrribute header
		segLen := int(adv.Data[cur])
		cur++
		segType := adv.Data[cur]
		cur++

		if (cur + segLen) >= total {
			// exit sielently
			break
		}

		// save parsed results
		result[segType] = adv.Data[cur : cur+segLen]

		cur += segLen
	}

	return &result
}

func findServicesForParsedAdvertisement(adv AdvertisementData) ServiceUUIDs {
	var head = ServiceUUIDs{}
	for segType := range adv {
		var dim = 0
		// FIXME we should define constants
		switch segType {
		case 2, 3: // incomplete/complete list of 16-bit UUIDs
			dim = 2
		case 4, 5: // incomplete list of 32-bit UUIDs
			dim = 4
		case 6, 7: // incomplete list of 128-bit UUIDs
			dim = 16
		}

		if dim > 0 {
			data := adv[segType]
			limit := len(data) - (dim - 1) // in go this statement ends up signed :)
			for i := 0; i < limit; i += dim {
				head = append(head, data[i:i+dim])
			}
		}
	}

	return head
}

//
// apiDelegate methods
//

// OnSystemBoot invoked when the BLED112 boots
func (dgt *apiDelegate) OnSystemBoot(info *SystemInfo) {

}

// OnSystemDebug invoked when BLED112 generates debug reply
func (dgt *apiDelegate) OnSystemDebug(data []byte) {

}

// OnSystemEndpointWatermarkRx inovked when receiveing Endpoint Watermark
func (dgt *apiDelegate) OnSystemEndpointWatermarkRx(endpoint byte, data byte) {

}

// OnSystemEndpointWatermarkTx inovked when transmitting Endpoint Watermark
func (dgt *apiDelegate) OnSystemEndpointWatermarkTx(endpoint byte, data byte) {

}

// OnSystemScriptFailure invoked on script failure
func (dgt *apiDelegate) OnSystemScriptFailure(addr uint16, reason uint16) {

}

// OnSystemNoLicenseKey invoked when no license key is found
func (dgt *apiDelegate) OnSystemNoLicenseKey() {

}

// OnFlashPsKey invoked when flash PS Key is updated
func (dgt *apiDelegate) OnFlashPsKey(key uint16, value []byte) {

}

// OnAttributeValue invoked when attribute value changes
func (dgt *apiDelegate) OnAttributeValue(connection byte, reason byte, handle uint16, offset uint16, value []byte) {

}

// OnAttributeUserReadRequest inovked by user read request
func (dgt *apiDelegate) OnAttributeUserReadRequest(connection byte, handle uint16, offset uint16, maxSize byte) {

}

// OnAttributeStatus invoked when status changes
func (dgt *apiDelegate) OnAttributeStatus(handle uint16, flags byte) {

}

// OnConnectionStatus invoked when the connection status changes
func (dgt *apiDelegate) OnConnectionStatus(status *ConnectionStatus) {
}

// OnConnectionVersionIndication invoked when version indication is updated
func (dgt *apiDelegate) OnConnectionVersionIndication(ind *ConnectionVersionIndication) {
}

// OnConnectionFeatureIndication invoked when feature indication is updated
func (dgt *apiDelegate) OnConnectionFeatureIndication(connection byte, features []byte) {
}

// OnConnectionRawRx invoked when raw data is received
func (dgt *apiDelegate) OnConnectionRawRx(connection byte, data []byte) {
}

// OnConnectionDisconnected invoked when the connection is lost
func (dgt *apiDelegate) OnConnectionDisconnected(connection byte, reason uint16) {
}

// OnAttrclientIndicated inovked when an attribute is indicated
func (dgt *apiDelegate) OnAttrclientIndicated(connection byte, attrHandle uint16) {
}

// OnAttrclientProcedureCompleted invoked upon procedure completion
func (dgt *apiDelegate) OnAttrclientProcedureCompleted(connection byte, result uint16, chrHandle uint16) {
}

// OnAttrclientGroupFound invoked when the group is found
func (dgt *apiDelegate) OnAttrclientGroupFound(connection byte, start uint16, end uint16, uuid []byte) {
}

// OnAttrclientAttributeFound invoked when the attribute is found
func (dgt *apiDelegate) OnAttrclientAttributeFound(connection byte, chrdecl uint16, value uint16, properties byte, uuid []byte) {
}

// OnAttrclientFindInformationFound invoked when information is available
func (dgt *apiDelegate) OnAttrclientFindInformationFound(connection byte, chrHandle uint16, uuid []byte) {
}

// OnAttrclientAttributeValue invoked when value changes
func (dgt *apiDelegate) OnAttrclientAttributeValue(connection byte, attHandle uint16, valueType byte, value []byte) {
}

// OnAttrclientReadMultipleResponse invoked when the client responds
func (dgt *apiDelegate) OnAttrclientReadMultipleResponse(connection byte, handles []byte) {}

// OnGapScanResponse invoked when GAP Scan Response is available
func (dgt *apiDelegate) OnGapScanResponse(resp *GapScanRespone) {
	// accumulate repsonses
	dgt.central.knownPeripherals[resp.Address.Hashable()] = resp
}

// OnGapModeChanged invoked when the GAP mode changes
func (dgt *apiDelegate) OnGapModeChanged(discover byte, connect byte) {

}

// OnSmSmpData invoked when security manager data is posted
func (dgt *apiDelegate) OnSmSmpData(handle byte, packet byte, data []byte) {}

// OnSmBondingFail invoked when the bonding fails
func (dgt *apiDelegate) OnSmBondingFail(handle byte, result uint16) {}

// OnSmPasskeyDisplay inovked when the paskey is displayed
func (dgt *apiDelegate) OnSmPasskeyDisplay(handle byte, passkey uint32) {}

// OnSmPasskeyRequest invoked when the paskey is requested
func (dgt *apiDelegate) OnSmPasskeyRequest(handle byte) {}

// OnSmBondStatus invoked when the bond status is updated
func (dgt *apiDelegate) OnSmBondStatus(status *SmBondStatus) {}

// OnHardwareIoPortStatus invoked when the IO port status is changed
func (dgt *apiDelegate) OnHardwareIoPortStatus(status *IoPortStatus) {}

// OnHardwareSoftTimer invoked upon soft timer expiry
func (dgt *apiDelegate) OnHardwareSoftTimer(handle byte) {}

// OnHardwareAdcResult invoked when ADC result is generated
func (dgt *apiDelegate) OnHardwareAdcResult(input byte, value int16) {}
