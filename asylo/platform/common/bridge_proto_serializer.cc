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

#include "asylo/platform/common/bridge_proto_serializer.h"

#include <sys/inotify.h>
#include <sys/types.h>

#include <string>

#include "asylo/platform/system_call/type_conversions/types_functions.h"

namespace asylo {
namespace {

bool ConvertToInotifyEventProtobuf(const struct inotify_event *event,
                                   InotifyEvent *event_proto) {
  if (!event || !event_proto) return false;
  event_proto->set_wd(event->wd);
  event_proto->set_mask(TokLinuxInotifyEventMask(event->mask));
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
    new_event_struct->mask = FromkLinuxInotifyEventMask(curr_event.mask());
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
