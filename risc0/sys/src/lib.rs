// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(feature = "cuda")]
pub mod cuda;

use std::ffi::CStr;

use anyhow::{anyhow, Result};

#[repr(C)]
pub struct CppError {
    msg: *const std::os::raw::c_char,
}

impl Drop for CppError {
    fn drop(&mut self) {
        extern "C" {
            fn free(str: *const std::os::raw::c_char);
        }
        unsafe { free(self.msg) };
    }
}

impl Default for CppError {
    fn default() -> Self {
        Self {
            msg: std::ptr::null(),
        }
    }
}

impl CppError {
    pub fn unwrap(self) {
        if !self.msg.is_null() {
            let c_str = unsafe { std::ffi::CStr::from_ptr(self.msg) };
            panic!("{}", c_str.to_str().unwrap_or("unknown error"));
        }
    }
}

pub fn ffi_wrap<F>(mut inner: F) -> Result<()>
where
    F: FnMut() -> *const std::os::raw::c_char, // 泛型函数，返回指向 C 字符串的指针
{
    // 声明外部 C 函数，用于释放 C 字符串指针
    extern "C" {
        fn free(str: *const std::os::raw::c_char);
    }

    // 调用传入的闭包函数，获取 C 字符串指针
    let c_ptr = inner();
    if c_ptr.is_null() {
        // 如果指针为空，表示没有错误，返回 Ok
        Ok(())
    } else {
        // 如果指针不为空，表示有错误信息
        let what = unsafe {
            // 将 C 字符串指针转换为 Rust 字符串
            let msg = CStr::from_ptr(c_ptr)
                .to_str() // 转换为 &str
                .unwrap_or("Invalid error msg pointer") // 如果转换失败，使用默认错误信息
                .to_string(); // 转换为 String
            free(c_ptr); // 释放 C 字符串指针
            msg // 返回错误信息
        };
        // 返回包含错误信息的 Err
        Err(anyhow!(what))
    }
}
