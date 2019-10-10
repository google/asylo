/*
 *
 * Copyright 2017 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string>

#include "asylo/platform/common/bridge_functions.h"
#include "asylo/platform/common/bridge_proto_serializer.h"
#include "asylo/platform/common/bridge_types.h"

namespace asylo {
namespace {

void ConvertToInotifyMaskProto(uint32_t mask,
                               google::protobuf::RepeatedField<int> *mask_proto) {
  if (mask & IN_ACCESS) mask_proto->Add(InotifyFlag::PROTO_ACCESS);
  if (mask & IN_ATTRIB) mask_proto->Add(InotifyFlag::PROTO_ATTRIB);
  if (mask & IN_CLOSE_WRITE) mask_proto->Add(InotifyFlag::PROTO_CLOSE_WRITE);
  if (mask & IN_CLOSE_NOWRITE)
    mask_proto->Add(InotifyFlag::PROTO_CLOSE_NOWRITE);
  if (mask & IN_CREATE) mask_proto->Add(InotifyFlag::PROTO_CREATE);
  if (mask & IN_DELETE) mask_proto->Add(InotifyFlag::PROTO_DELETE);
  if (mask & IN_DELETE_SELF) mask_proto->Add(InotifyFlag::PROTO_DELETE_SELF);
  if (mask & IN_MODIFY) mask_proto->Add(InotifyFlag::PROTO_MODIFY);
  if (mask & IN_MOVE_SELF) mask_proto->Add(InotifyFlag::PROTO_MOVE_SELF);
  if (mask & IN_MOVED_FROM) mask_proto->Add(InotifyFlag::PROTO_MOVED_FROM);
  if (mask & IN_MOVED_TO) mask_proto->Add(InotifyFlag::PROTO_MOVED_TO);
  if (mask & IN_OPEN) mask_proto->Add(InotifyFlag::PROTO_OPEN);
  if (mask & IN_DONT_FOLLOW) mask_proto->Add(InotifyFlag::PROTO_DONT_FOLLOW);
  if (mask & IN_EXCL_UNLINK) mask_proto->Add(InotifyFlag::PROTO_EXCL_UNLINK);
  if (mask & IN_MASK_ADD) mask_proto->Add(InotifyFlag::PROTO_MASK_ADD);
  if (mask & IN_ONESHOT) mask_proto->Add(InotifyFlag::PROTO_ONESHOT);
  if (mask & IN_ONLYDIR) mask_proto->Add(InotifyFlag::PROTO_ONLYDIR);
  if (mask & IN_IGNORED) mask_proto->Add(InotifyFlag::PROTO_IGNORED);
  if (mask & IN_ISDIR) mask_proto->Add(InotifyFlag::PROTO_ISDIR);
  if (mask & IN_Q_OVERFLOW) mask_proto->Add(InotifyFlag::PROTO_Q_OVERFLOW);
  if (mask & IN_UNMOUNT) mask_proto->Add(InotifyFlag::PROTO_UNMOUNT);
}

uint32_t ConvertFromInotifyMaskProto(
    const google::protobuf::RepeatedField<int> &mask_proto) {
  uint32_t flags = 0;
  for (int i = 0; i < mask_proto.size(); ++i) {
    int curr_flag = mask_proto.Get(i);
    if (curr_flag == InotifyFlag::PROTO_ACCESS)
      flags |= IN_ACCESS;
    else if (curr_flag == InotifyFlag::PROTO_ATTRIB)
      flags |= IN_ATTRIB;
    else if (curr_flag == InotifyFlag::PROTO_CLOSE_WRITE)
      flags |= IN_CLOSE_WRITE;
    else if (curr_flag == InotifyFlag::PROTO_CLOSE_NOWRITE)
      flags |= IN_CLOSE_NOWRITE;
    else if (curr_flag == InotifyFlag::PROTO_CREATE)
      flags |= IN_CREATE;
    else if (curr_flag == InotifyFlag::PROTO_DELETE)
      flags |= IN_DELETE;
    else if (curr_flag == InotifyFlag::PROTO_DELETE_SELF)
      flags |= IN_DELETE_SELF;
    else if (curr_flag == InotifyFlag::PROTO_MODIFY)
      flags |= IN_MODIFY;
    else if (curr_flag == InotifyFlag::PROTO_MOVE_SELF)
      flags |= IN_MOVE_SELF;
    else if (curr_flag == InotifyFlag::PROTO_MOVED_FROM)
      flags |= IN_MOVED_FROM;
    else if (curr_flag == InotifyFlag::PROTO_MOVED_TO)
      flags |= IN_MOVED_TO;
    else if (curr_flag == InotifyFlag::PROTO_OPEN)
      flags |= IN_OPEN;
    else if (curr_flag == InotifyFlag::PROTO_DONT_FOLLOW)
      flags |= IN_DONT_FOLLOW;
    else if (curr_flag == InotifyFlag::PROTO_EXCL_UNLINK)
      flags |= IN_EXCL_UNLINK;
    else if (curr_flag == InotifyFlag::PROTO_MASK_ADD)
      flags |= IN_MASK_ADD;
    else if (curr_flag == InotifyFlag::PROTO_ONESHOT)
      flags |= IN_ONESHOT;
    else if (curr_flag == InotifyFlag::PROTO_ONLYDIR)
      flags |= IN_ONLYDIR;
    else if (curr_flag == InotifyFlag::PROTO_IGNORED)
      flags |= IN_IGNORED;
    else if (curr_flag == InotifyFlag::PROTO_ISDIR)
      flags |= IN_ISDIR;
    else if (curr_flag == InotifyFlag::PROTO_Q_OVERFLOW)
      flags |= IN_Q_OVERFLOW;
    else if (curr_flag == InotifyFlag::PROTO_UNMOUNT)
      flags |= IN_UNMOUNT;
  }
  return flags;
}

bool ConvertToInotifyEventProtobuf(const struct inotify_event *event,
                                   InotifyEvent *event_proto) {
  if (!event || !event_proto) return false;
  event_proto->set_wd(event->wd);
  ConvertToInotifyMaskProto(event->mask, event_proto->mutable_mask());
  event_proto->set_cookie(event->cookie);
  if (event->len) {
    event_proto->set_name(event->name);
  }
  return true;
}

bool ConvertToInotifyEventList(char *buf, size_t buf_len,
                               InotifyEventList *event_list) {
  char *curr_event_ptr = buf;
  while (curr_event_ptr < buf + buf_len) {
    struct inotify_event *curr_event =
        reinterpret_cast<struct inotify_event *>(curr_event_ptr);
    if (!ConvertToInotifyEventProtobuf(curr_event, event_list->add_events()))
      return false;
    curr_event_ptr += sizeof(struct inotify_event) + curr_event->len;
  }
  return true;
}

void AddToInotifyEventQueue(const InotifyEventList &event_list,
                            std::queue<struct inotify_event *> *event_structs) {
  for (int i = 0; i < event_list.events().size(); ++i) {
    const InotifyEvent &curr_event = event_list.events(i);
    // The len field accounts for the null-terminator.
    uint32_t len = 0;
    if (curr_event.has_name()) {
      len = curr_event.name().length() + 1;
    }
    // The caller is responsible for deallocating the memory allocated below.
    struct inotify_event *new_event_struct =
        static_cast<struct inotify_event *>(
            malloc(sizeof(struct inotify_event) + len));
    new_event_struct->wd = curr_event.wd();
    new_event_struct->mask = ConvertFromInotifyMaskProto(curr_event.mask());
    new_event_struct->cookie = curr_event.cookie();
    new_event_struct->len = len;
    if (len) {
      memcpy(new_event_struct->name, curr_event.name().c_str(), len);
    }
    event_structs->push(new_event_struct);
  }
}

}  // namespace

bool SerializeInotifyEvents(char *buf, size_t buf_len, char **out,
                            size_t *len) {
  InotifyEventList event_list_proto;
  if (ConvertToInotifyEventList(buf, buf_len, &event_list_proto)) {
    *len = event_list_proto.ByteSizeLong();
    // The caller is responsible for freeing the memory below.
    *out = static_cast<char *>(malloc(*len));
    return event_list_proto.SerializeToArray(*out, *len);
  }
  return false;
}

bool DeserializeInotifyEvents(absl::string_view in,
                              std::queue<struct inotify_event *> *events) {
  if (!events) return false;
  InotifyEventList event_list_proto;
  if (!event_list_proto.ParseFromArray(in.data(), in.length())) return false;
  AddToInotifyEventQueue(event_list_proto, events);
  return true;
}

}  // namespace asylo
