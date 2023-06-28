// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: auth/auth.proto

package auth

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AddPolicyReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token        string   `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	User         string   `protobuf:"bytes,2,opt,name=user,proto3" json:"user,omitempty"`
	Computation  string   `protobuf:"bytes,3,opt,name=computation,proto3" json:"computation,omitempty"`
	CloudRole    []string `protobuf:"bytes,4,rep,name=cloudRole,proto3" json:"cloudRole,omitempty"`
	ManifestRole []string `protobuf:"bytes,5,rep,name=manifestRole,proto3" json:"manifestRole,omitempty"`
	PublicKey    string   `protobuf:"bytes,6,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
}

func (x *AddPolicyReq) Reset() {
	*x = AddPolicyReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_auth_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddPolicyReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddPolicyReq) ProtoMessage() {}

func (x *AddPolicyReq) ProtoReflect() protoreflect.Message {
	mi := &file_auth_auth_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddPolicyReq.ProtoReflect.Descriptor instead.
func (*AddPolicyReq) Descriptor() ([]byte, []int) {
	return file_auth_auth_proto_rawDescGZIP(), []int{0}
}

func (x *AddPolicyReq) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *AddPolicyReq) GetUser() string {
	if x != nil {
		return x.User
	}
	return ""
}

func (x *AddPolicyReq) GetComputation() string {
	if x != nil {
		return x.Computation
	}
	return ""
}

func (x *AddPolicyReq) GetCloudRole() []string {
	if x != nil {
		return x.CloudRole
	}
	return nil
}

func (x *AddPolicyReq) GetManifestRole() []string {
	if x != nil {
		return x.ManifestRole
	}
	return nil
}

func (x *AddPolicyReq) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

type AddPolicyRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Added bool `protobuf:"varint,1,opt,name=added,proto3" json:"added,omitempty"`
}

func (x *AddPolicyRes) Reset() {
	*x = AddPolicyRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_auth_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddPolicyRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddPolicyRes) ProtoMessage() {}

func (x *AddPolicyRes) ProtoReflect() protoreflect.Message {
	mi := &file_auth_auth_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddPolicyRes.ProtoReflect.Descriptor instead.
func (*AddPolicyRes) Descriptor() ([]byte, []int) {
	return file_auth_auth_proto_rawDescGZIP(), []int{1}
}

func (x *AddPolicyRes) GetAdded() bool {
	if x != nil {
		return x.Added
	}
	return false
}

type UpdatePolicyReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token        string   `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	User         string   `protobuf:"bytes,2,opt,name=user,proto3" json:"user,omitempty"`
	Computation  string   `protobuf:"bytes,3,opt,name=computation,proto3" json:"computation,omitempty"`
	CloudRole    []string `protobuf:"bytes,4,rep,name=cloudRole,proto3" json:"cloudRole,omitempty"`
	ManifestRole []string `protobuf:"bytes,5,rep,name=manifestRole,proto3" json:"manifestRole,omitempty"`
}

func (x *UpdatePolicyReq) Reset() {
	*x = UpdatePolicyReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_auth_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdatePolicyReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdatePolicyReq) ProtoMessage() {}

func (x *UpdatePolicyReq) ProtoReflect() protoreflect.Message {
	mi := &file_auth_auth_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdatePolicyReq.ProtoReflect.Descriptor instead.
func (*UpdatePolicyReq) Descriptor() ([]byte, []int) {
	return file_auth_auth_proto_rawDescGZIP(), []int{2}
}

func (x *UpdatePolicyReq) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *UpdatePolicyReq) GetUser() string {
	if x != nil {
		return x.User
	}
	return ""
}

func (x *UpdatePolicyReq) GetComputation() string {
	if x != nil {
		return x.Computation
	}
	return ""
}

func (x *UpdatePolicyReq) GetCloudRole() []string {
	if x != nil {
		return x.CloudRole
	}
	return nil
}

func (x *UpdatePolicyReq) GetManifestRole() []string {
	if x != nil {
		return x.ManifestRole
	}
	return nil
}

type UpdatePolicyRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Updated bool `protobuf:"varint,1,opt,name=updated,proto3" json:"updated,omitempty"`
}

func (x *UpdatePolicyRes) Reset() {
	*x = UpdatePolicyRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_auth_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdatePolicyRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdatePolicyRes) ProtoMessage() {}

func (x *UpdatePolicyRes) ProtoReflect() protoreflect.Message {
	mi := &file_auth_auth_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdatePolicyRes.ProtoReflect.Descriptor instead.
func (*UpdatePolicyRes) Descriptor() ([]byte, []int) {
	return file_auth_auth_proto_rawDescGZIP(), []int{3}
}

func (x *UpdatePolicyRes) GetUpdated() bool {
	if x != nil {
		return x.Updated
	}
	return false
}

type DeletePolicyReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Token       string `protobuf:"bytes,1,opt,name=token,proto3" json:"token,omitempty"`
	User        string `protobuf:"bytes,2,opt,name=user,proto3" json:"user,omitempty"`
	Computation string `protobuf:"bytes,3,opt,name=computation,proto3" json:"computation,omitempty"`
}

func (x *DeletePolicyReq) Reset() {
	*x = DeletePolicyReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_auth_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeletePolicyReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeletePolicyReq) ProtoMessage() {}

func (x *DeletePolicyReq) ProtoReflect() protoreflect.Message {
	mi := &file_auth_auth_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeletePolicyReq.ProtoReflect.Descriptor instead.
func (*DeletePolicyReq) Descriptor() ([]byte, []int) {
	return file_auth_auth_proto_rawDescGZIP(), []int{4}
}

func (x *DeletePolicyReq) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *DeletePolicyReq) GetUser() string {
	if x != nil {
		return x.User
	}
	return ""
}

func (x *DeletePolicyReq) GetComputation() string {
	if x != nil {
		return x.Computation
	}
	return ""
}

type DeletePolicyRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Deleted bool `protobuf:"varint,1,opt,name=deleted,proto3" json:"deleted,omitempty"`
}

func (x *DeletePolicyRes) Reset() {
	*x = DeletePolicyRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_auth_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeletePolicyRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeletePolicyRes) ProtoMessage() {}

func (x *DeletePolicyRes) ProtoReflect() protoreflect.Message {
	mi := &file_auth_auth_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeletePolicyRes.ProtoReflect.Descriptor instead.
func (*DeletePolicyRes) Descriptor() ([]byte, []int) {
	return file_auth_auth_proto_rawDescGZIP(), []int{5}
}

func (x *DeletePolicyRes) GetDeleted() bool {
	if x != nil {
		return x.Deleted
	}
	return false
}

type AuthorizeReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	User        string `protobuf:"bytes,1,opt,name=user,proto3" json:"user,omitempty"`
	Computation string `protobuf:"bytes,2,opt,name=computation,proto3" json:"computation,omitempty"`
	Role        string `protobuf:"bytes,3,opt,name=role,proto3" json:"role,omitempty"`
	Domain      string `protobuf:"bytes,4,opt,name=domain,proto3" json:"domain,omitempty"`
}

func (x *AuthorizeReq) Reset() {
	*x = AuthorizeReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_auth_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthorizeReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthorizeReq) ProtoMessage() {}

func (x *AuthorizeReq) ProtoReflect() protoreflect.Message {
	mi := &file_auth_auth_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthorizeReq.ProtoReflect.Descriptor instead.
func (*AuthorizeReq) Descriptor() ([]byte, []int) {
	return file_auth_auth_proto_rawDescGZIP(), []int{6}
}

func (x *AuthorizeReq) GetUser() string {
	if x != nil {
		return x.User
	}
	return ""
}

func (x *AuthorizeReq) GetComputation() string {
	if x != nil {
		return x.Computation
	}
	return ""
}

func (x *AuthorizeReq) GetRole() string {
	if x != nil {
		return x.Role
	}
	return ""
}

func (x *AuthorizeReq) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

type AuthorizeRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Authorized bool `protobuf:"varint,1,opt,name=authorized,proto3" json:"authorized,omitempty"`
}

func (x *AuthorizeRes) Reset() {
	*x = AuthorizeRes{}
	if protoimpl.UnsafeEnabled {
		mi := &file_auth_auth_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthorizeRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthorizeRes) ProtoMessage() {}

func (x *AuthorizeRes) ProtoReflect() protoreflect.Message {
	mi := &file_auth_auth_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthorizeRes.ProtoReflect.Descriptor instead.
func (*AuthorizeRes) Descriptor() ([]byte, []int) {
	return file_auth_auth_proto_rawDescGZIP(), []int{7}
}

func (x *AuthorizeRes) GetAuthorized() bool {
	if x != nil {
		return x.Authorized
	}
	return false
}

var File_auth_auth_proto protoreflect.FileDescriptor

var file_auth_auth_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x61, 0x75, 0x74, 0x68, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x18, 0x75, 0x6c, 0x74, 0x72, 0x61, 0x76, 0x69, 0x6f, 0x6c, 0x65, 0x74, 0x72, 0x73,
	0x2e, 0x63, 0x6f, 0x63, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x22, 0xba, 0x01, 0x0a, 0x0c,
	0x41, 0x64, 0x64, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x71, 0x12, 0x14, 0x0a, 0x05,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b,
	0x65, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f, 0x6d,
	0x70, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x6c, 0x6f, 0x75,
	0x64, 0x52, 0x6f, 0x6c, 0x65, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x09, 0x63, 0x6c, 0x6f,
	0x75, 0x64, 0x52, 0x6f, 0x6c, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65,
	0x73, 0x74, 0x52, 0x6f, 0x6c, 0x65, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0c, 0x6d, 0x61,
	0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x52, 0x6f, 0x6c, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x70, 0x75,
	0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x22, 0x24, 0x0a, 0x0c, 0x41, 0x64, 0x64, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x64, 0x64, 0x65,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x61, 0x64, 0x64, 0x65, 0x64, 0x22, 0x9f,
	0x01, 0x0a, 0x0f, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52,
	0x65, 0x71, 0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12, 0x20, 0x0a, 0x0b,
	0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1c,
	0x0a, 0x09, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x52, 0x6f, 0x6c, 0x65, 0x18, 0x04, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x09, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x52, 0x6f, 0x6c, 0x65, 0x12, 0x22, 0x0a, 0x0c,
	0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x52, 0x6f, 0x6c, 0x65, 0x18, 0x05, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x0c, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74, 0x52, 0x6f, 0x6c, 0x65,
	0x22, 0x2b, 0x0a, 0x0f, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79,
	0x52, 0x65, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x22, 0x5d, 0x0a,
	0x0f, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x71,
	0x12, 0x14, 0x0a, 0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x6f,
	0x6d, 0x70, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0b, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x2b, 0x0a, 0x0f,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x73, 0x12,
	0x18, 0x0a, 0x07, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x07, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x22, 0x70, 0x0a, 0x0c, 0x41, 0x75, 0x74,
	0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x52, 0x65, 0x71, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x73, 0x65,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12, 0x20, 0x0a,
	0x0b, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x12, 0x0a, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x72,
	0x6f, 0x6c, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x22, 0x2e, 0x0a, 0x0c, 0x41,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x52, 0x65, 0x73, 0x12, 0x1e, 0x0a, 0x0a, 0x61,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x0a, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x32, 0x9b, 0x03, 0x0a, 0x0b,
	0x41, 0x75, 0x74, 0x68, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x5d, 0x0a, 0x09, 0x41,
	0x64, 0x64, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x26, 0x2e, 0x75, 0x6c, 0x74, 0x72, 0x61,
	0x76, 0x69, 0x6f, 0x6c, 0x65, 0x74, 0x72, 0x73, 0x2e, 0x63, 0x6f, 0x63, 0x6f, 0x73, 0x2e, 0x61,
	0x75, 0x74, 0x68, 0x2e, 0x41, 0x64, 0x64, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x71,
	0x1a, 0x26, 0x2e, 0x75, 0x6c, 0x74, 0x72, 0x61, 0x76, 0x69, 0x6f, 0x6c, 0x65, 0x74, 0x72, 0x73,
	0x2e, 0x63, 0x6f, 0x63, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x41, 0x64, 0x64, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x66, 0x0a, 0x0c, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x12, 0x29, 0x2e, 0x75, 0x6c, 0x74,
	0x72, 0x61, 0x76, 0x69, 0x6f, 0x6c, 0x65, 0x74, 0x72, 0x73, 0x2e, 0x63, 0x6f, 0x63, 0x6f, 0x73,
	0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x52, 0x65, 0x71, 0x1a, 0x29, 0x2e, 0x75, 0x6c, 0x74, 0x72, 0x61, 0x76, 0x69, 0x6f,
	0x6c, 0x65, 0x74, 0x72, 0x73, 0x2e, 0x63, 0x6f, 0x63, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68,
	0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x73,
	0x22, 0x00, 0x12, 0x66, 0x0a, 0x0c, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x50, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x12, 0x29, 0x2e, 0x75, 0x6c, 0x74, 0x72, 0x61, 0x76, 0x69, 0x6f, 0x6c, 0x65, 0x74,
	0x72, 0x73, 0x2e, 0x63, 0x6f, 0x63, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x44, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x71, 0x1a, 0x29, 0x2e,
	0x75, 0x6c, 0x74, 0x72, 0x61, 0x76, 0x69, 0x6f, 0x6c, 0x65, 0x74, 0x72, 0x73, 0x2e, 0x63, 0x6f,
	0x63, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x5d, 0x0a, 0x09, 0x41, 0x75,
	0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x12, 0x26, 0x2e, 0x75, 0x6c, 0x74, 0x72, 0x61, 0x76,
	0x69, 0x6f, 0x6c, 0x65, 0x74, 0x72, 0x73, 0x2e, 0x63, 0x6f, 0x63, 0x6f, 0x73, 0x2e, 0x61, 0x75,
	0x74, 0x68, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x52, 0x65, 0x71, 0x1a,
	0x26, 0x2e, 0x75, 0x6c, 0x74, 0x72, 0x61, 0x76, 0x69, 0x6f, 0x6c, 0x65, 0x74, 0x72, 0x73, 0x2e,
	0x63, 0x6f, 0x63, 0x6f, 0x73, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6f,
	0x72, 0x69, 0x7a, 0x65, 0x52, 0x65, 0x73, 0x22, 0x00, 0x42, 0x08, 0x5a, 0x06, 0x2e, 0x2f, 0x61,
	0x75, 0x74, 0x68, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_auth_auth_proto_rawDescOnce sync.Once
	file_auth_auth_proto_rawDescData = file_auth_auth_proto_rawDesc
)

func file_auth_auth_proto_rawDescGZIP() []byte {
	file_auth_auth_proto_rawDescOnce.Do(func() {
		file_auth_auth_proto_rawDescData = protoimpl.X.CompressGZIP(file_auth_auth_proto_rawDescData)
	})
	return file_auth_auth_proto_rawDescData
}

var file_auth_auth_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_auth_auth_proto_goTypes = []interface{}{
	(*AddPolicyReq)(nil),    // 0: ultravioletrs.cocos.auth.AddPolicyReq
	(*AddPolicyRes)(nil),    // 1: ultravioletrs.cocos.auth.AddPolicyRes
	(*UpdatePolicyReq)(nil), // 2: ultravioletrs.cocos.auth.UpdatePolicyReq
	(*UpdatePolicyRes)(nil), // 3: ultravioletrs.cocos.auth.UpdatePolicyRes
	(*DeletePolicyReq)(nil), // 4: ultravioletrs.cocos.auth.DeletePolicyReq
	(*DeletePolicyRes)(nil), // 5: ultravioletrs.cocos.auth.DeletePolicyRes
	(*AuthorizeReq)(nil),    // 6: ultravioletrs.cocos.auth.AuthorizeReq
	(*AuthorizeRes)(nil),    // 7: ultravioletrs.cocos.auth.AuthorizeRes
}
var file_auth_auth_proto_depIdxs = []int32{
	0, // 0: ultravioletrs.cocos.auth.AuthService.AddPolicy:input_type -> ultravioletrs.cocos.auth.AddPolicyReq
	2, // 1: ultravioletrs.cocos.auth.AuthService.UpdatePolicy:input_type -> ultravioletrs.cocos.auth.UpdatePolicyReq
	4, // 2: ultravioletrs.cocos.auth.AuthService.DeletePolicy:input_type -> ultravioletrs.cocos.auth.DeletePolicyReq
	6, // 3: ultravioletrs.cocos.auth.AuthService.Authorize:input_type -> ultravioletrs.cocos.auth.AuthorizeReq
	1, // 4: ultravioletrs.cocos.auth.AuthService.AddPolicy:output_type -> ultravioletrs.cocos.auth.AddPolicyRes
	3, // 5: ultravioletrs.cocos.auth.AuthService.UpdatePolicy:output_type -> ultravioletrs.cocos.auth.UpdatePolicyRes
	5, // 6: ultravioletrs.cocos.auth.AuthService.DeletePolicy:output_type -> ultravioletrs.cocos.auth.DeletePolicyRes
	7, // 7: ultravioletrs.cocos.auth.AuthService.Authorize:output_type -> ultravioletrs.cocos.auth.AuthorizeRes
	4, // [4:8] is the sub-list for method output_type
	0, // [0:4] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_auth_auth_proto_init() }
func file_auth_auth_proto_init() {
	if File_auth_auth_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_auth_auth_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddPolicyReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_auth_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddPolicyRes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_auth_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdatePolicyReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_auth_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdatePolicyRes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_auth_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeletePolicyReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_auth_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeletePolicyRes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_auth_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthorizeReq); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_auth_auth_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthorizeRes); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_auth_auth_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_auth_auth_proto_goTypes,
		DependencyIndexes: file_auth_auth_proto_depIdxs,
		MessageInfos:      file_auth_auth_proto_msgTypes,
	}.Build()
	File_auth_auth_proto = out.File
	file_auth_auth_proto_rawDesc = nil
	file_auth_auth_proto_goTypes = nil
	file_auth_auth_proto_depIdxs = nil
}
