package captchautils

import (
	"encoding/json"
)

/*
MAKE SURE THAT THE DEFINITIONS IN GO LINE UP EXACTLY IN THE SAME ORDER AS WHAT OCCURS ON IN CLIENT SIDE OTHERWISE THE
MARSHALLING PRODUCES A DIFFERENT JSON SERIALIZED STRING WHICH RESULTS IN AN INCORRECT HMAC
*/

type ChainTile struct {
	Row int    `json:"row"`
	Col int    `json:"col"`
	Id  string `json:"id"`
}

// func (ct *ChainTile) MarshalBinary() ([]byte, error) {
// 	jsonString := fmt.Sprintf(`{"id":"%s","row":%d,"col":%d"}`, ct.Id, ct.Row, ct.Col)
// 	return []byte(jsonString), nil
// }

func (ct *ChainTile) MarshalBinary() ([]byte, error) {
	return json.Marshal(ct)
}

func (ct *ChainTile) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, ct)
}

type ClickChainEntry struct {
	TimeStamp       string    `json:"time_stamp"`
	TileClicked     ChainTile `json:"tile_clicked"`
	TileSwappedWith ChainTile `json:"tile_swapped_with"`

	ClickCount int    `json:"click_count"`
	Hash       string `json:"hash"`
}

func (chainEntry *ClickChainEntry) MarshalBinary() ([]byte, error) {
	return json.Marshal(chainEntry)
}

func (chainEntry *ClickChainEntry) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, chainEntry)
}

func (chainEntry *ClickChainEntry) JSONBytesToString(data []byte) string {
	return string(data)
}

// func (chainEntry *ClickChainEntry) MarshalBinary() ([]byte, error) {

// 	marshaledTileClicked, err := chainEntry.TileClicked.MarshalBinary()
// 	if err != nil {
// 		return nil, fmt.Errorf("ErrFailedChainTileMarshalBinary: %v", err)
// 	}

// 	marshaledTileSwappedWith, err := chainEntry.TileSwappedWith.MarshalBinary()
// 	if err != nil {
// 		return nil, fmt.Errorf("ErrFailedChainTileMarshalBinary: %v", err)
// 	}

// 	jsonString := fmt.Sprintf(
// 		`{"time_stamp":"%s","tile_clicked":%s,"tile_swapped_with":%s,"click_count":%d,"hash":"%s"}`,
// 		chainEntry.TimeStamp,
// 		marshaledTileClicked,
// 		marshaledTileSwappedWith,
// 		chainEntry.ClickCount,
// 		chainEntry.Hash,
// 	)
// 	return []byte(jsonString), nil
// }
