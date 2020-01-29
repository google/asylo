/*
 *
 * Copyright 2019 Asylo authors
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

package com.asylo.client;

/**
 * A closeable Java wrapper to hold a native object pointer.
 *
 * <p>Child classes will map to the corresponding Asylo C++ classes. Objects of the child classes
 * will also have memory allocated in the native heap. Java's garbage collector does not manage
 * native memory, therefore, these objects must be explicitly closed.
 *
 * <p>Closing the objects of the inherited classes will denote that they are no longer needed and
 * its native memory can be released. Inherited classes need to deallocate any resources, or memory
 * allocated for the native objects when {@link #closeNative(long)} is invoked. After closing an
 * object, it is unsafe to use that object or call its APIs and it can lead to undefined behavior.
 */
public abstract class AutoCloseablePointer implements AutoCloseable {

  private long pointer;

  protected AutoCloseablePointer(final long pointer) {
    this.pointer = pointer;
  }

  protected final long getPointer() {
    return pointer;
  }

  /**
   * This function hands over control to the child class by calling {@link #closeNative(long)} for
   * cleaning up the native resources and memory.
   *
   * <p>After a successful call it resets the pointer to 0 and all future invocations of this
   * function will be ignored.
   */
  @Override
  public void close() {
    if (pointer != 0) {
      closeNative(pointer);
      pointer = 0;
    }
  }

  /**
   * Child classes should free up native resources and memory when this function is invoked.
   *
   * @param pointer Pointer value of the corresponding native object.
   */
  protected abstract void closeNative(final long pointer);
}
