package model

type NotificationEvent struct {
	ID         string                 `json:"id,omitempty"`
	Name       string                 `json:"name,omitempty"`
	Email      string                 `json:"email,omitempty"`
	Phone      *string                `json:"phone,omitempty"`
	Type       string                 `json:"type,omitempty"`
	TemplateID string                 `json:"template_id,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	CreatedAt  string                 `json:"created_at,omitempty"`
	UpdatedAt  string                 `json:"updated_at,omitempty"`
}

func (n *NotificationEvent) GetId() string {
	return n.ID
}
