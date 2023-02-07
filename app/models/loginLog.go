package models

import (
	mgo "github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	mgodo "github.com/lujiacn/mgodo"
)

type LoginLog struct {
	mgodo.BaseModel `bson:",inline"`
	Account         string `bson:"Account,omitempty"`
	Status          string `bson:"Status,omitempty"`
	IPAddress       string `bson:"IPAddress,omitempty"`
	User            *User  `bson:"-"`
}

func (m *LoginLog) GenUser(s *mgo.Session) {
	user := new(User)
	do := mgodo.New(s, user)
	do.Query = bson.M{"Identity": m.Account}
	do.GetByQ()
	m.User = user
}
