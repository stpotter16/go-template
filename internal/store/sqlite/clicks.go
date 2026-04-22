package sqlite

import (
	"context"

	"github.com/stpotter16/go-template/internal/types"
)

func (s Store) GetClicks(ctx context.Context) ([]types.Click, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, created_time from clicks`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clicks []types.Click

	for rows.Next() {
		var click types.Click
		var createdTime string
		if err := rows.Scan(&click.ID, &createdTime); err != nil {
			return nil, err
		}
		click.CreatedTime, err = parseTime(createdTime)
		if err != nil {
			return nil, err
		}
		clicks = append(clicks, click)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return clicks, nil
}
