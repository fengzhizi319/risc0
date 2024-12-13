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

use std::{
    collections::{BTreeMap, BTreeSet},
    mem::take,
};

use anyhow::Result;
use risc0_binfmt::{MemoryImage, SystemState};
use risc0_zkp::core::hash::sha::BLOCK_BYTES;
use risc0_zkvm_platform::{PAGE_SIZE, WORD_SIZE};

use super::addr::{ByteAddr, WordAddr};

pub const PAGE_WORDS: usize = PAGE_SIZE / WORD_SIZE;

/// The number of blocks that fit within a single page.
const BLOCKS_PER_PAGE: usize = PAGE_SIZE / BLOCK_BYTES;

const SHA_INIT: usize = 5;
const SHA_LOAD: usize = 16;
const SHA_MAIN: usize = 52;

const INVALID_IDX: u32 = u32::MAX;
const NUM_PAGES: usize = 256 * 1024;

const fn cycles_per_page(blocks_per_page: usize) -> usize {
    1 + SHA_INIT + (SHA_LOAD + SHA_MAIN) * blocks_per_page
}

struct Page(Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
enum PageState {
    Loaded,
    Dirty,
}

#[derive(Clone, Default, Debug)]
pub struct PageFaults {
    pub reads: BTreeSet<u32>,
    pub writes: BTreeSet<u32>,
}

#[derive(Clone, Debug)]
enum Action {
    PageRead(u32, usize),
    PageWrite(u32, usize, bool),
    Store(WordAddr, u32),
}

pub struct PagedMemory {
    // 保存内存镜像信息，包括程序计数器和 Merkle 树根等
    pub image: MemoryImage,
    // 页面表，用于映射页面索引到缓存索引
    page_table: Vec<u32>,
    // 页面缓存，缓存已加载的页面数据
    page_cache: Vec<Page>,
    // 页面状态，保存每个页面的状态（如已加载、脏页等）
    page_states: BTreeMap<u32, PageState>,
    // 记录分页操作所消耗的周期数
    pub cycles: usize,
    // 记录挂起的页面读写操作
    pending_actions: Vec<Action>,
}

impl PagedMemory {
    pub fn new(image: MemoryImage) -> Self {
        Self {
            image,
            page_table: vec![INVALID_IDX; NUM_PAGES],
            page_cache: Vec::new(),
            page_states: BTreeMap::new(),
            cycles: 0,
            pending_actions: Vec::new(),
        }
    }

    pub fn pre_peek(&self, addr: WordAddr) -> Result<u32> {
        let mut bytes = [0u8; WORD_SIZE];
        let addr: ByteAddr = addr.into();
        self.image.load_region_in_page(addr.0, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn peek(&self, addr: WordAddr) -> Result<u32> {
        let page_idx = addr.page_idx();
        let idx = self.page_table[page_idx as usize];
        if idx == INVALID_IDX {
            self.pre_peek(addr)
        } else {
            Ok(self.page_cache[idx as usize].load(addr))
        }
    }

    pub fn load(&mut self, addr: WordAddr) -> u32 {
        // 获取地址对应的页面索引
        let page_idx = addr.page_idx();
        // 记录调试信息，显示加载的地址和页面索引
        // tracing::trace!("load: {addr:?}, page: 0x{page_idx:05x}");
        // 获取页面表中对应页面索引的缓存索引
        let mut idx = self.page_table[page_idx as usize];
        // 如果缓存索引无效，则加载页面
        if idx == INVALID_IDX {
            self.load_page(page_idx);
            // 更新缓存索引
            idx = self.page_table[page_idx as usize];
        }
        // 从缓存中加载地址对应的数据并返回
        self.page_cache[idx as usize].load(addr)
    }

    pub fn store(&mut self, addr: WordAddr, data: u32) -> Result<()> {
        // 获取地址对应的页面索引
        let page_idx = addr.page_idx();
        // 记录调试信息，显示存储的地址、页面索引和数据
        // tracing::trace!("store: {addr:?}, page: {page_idx:#07x}, data: {data:#010x}");

        // 获取页面状态，如果页面状态不存在，则加载页面并设置状态为已加载
        let state = if let Some(state) = self.page_states.get(&page_idx) {
            *state
        } else {
            self.load_page(page_idx);
            PageState::Loaded
        };

        // 如果页面状态为已加载，则更新页面状态为脏页并记录页面状态变化
        if state == PageState::Loaded {
            self.update(page_idx, PageState::Dirty);
            self.page_changed(page_idx, PageState::Dirty);
        }

        // 获取页面表中对应页面索引的缓存索引
        let idx = self.page_table[page_idx as usize] as usize;
        // 获取缓存中的页面数据
        let page = self.page_cache.get_mut(idx).unwrap();
        // 从页面中加载旧数据
        let old = page.load(addr);
        // 记录存储操作，将旧数据添加到挂起操作列表中
        self.pending_actions.push(Action::Store(addr, old));
        // 将新数据存储到页面中
        page.store(addr, data);

        Ok(())
    }
    ///commit 函数的主要功能是提交当前的内存状态，并返回执行前后的系统状态和内存镜像
    pub fn commit(&mut self, pc: ByteAddr) -> (SystemState, MemoryImage, SystemState) {
        let pre_state = self.image.get_system_state();
        let info = &self.image.info;

        let mut image = MemoryImage {
            pages: BTreeMap::new(),
            info: info.clone(),
            pc: pre_state.pc,
        };

        for (page_idx, page_state) in &self.page_states {
            // Copy 'original' version of all pages, this is just the subset of
            // pages for the previous segment.
            image
                .pages
                .insert(*page_idx, self.image.load_page(*page_idx));

            // Update all 'dirty' pages into the image that accumulates over
            // segments.
            if *page_state == PageState::Dirty {
                let idx = self.page_table[*page_idx as usize] as usize;
                let page = &self.page_cache[idx];
                self.image.pages.insert(*page_idx, page.0.clone());
            }
        }

        // Update the merkle tree
        for (page_idx, page_state) in &self.page_states {
            if *page_state == PageState::Dirty {
                tracing::trace!("dirty: 0x{page_idx:05x}");
                self.image.update_page(*page_idx);
            }
        }
        self.image.pc = pc.0;
        let post_state = self.image.get_system_state();

        (pre_state, image, post_state)
    }

    pub fn undo(&mut self) {
        let pending_actions = take(&mut self.pending_actions);
        for action in pending_actions.iter().rev() {
            tracing::debug!("undo: {action:08x?})");
            match action {
                Action::PageRead(page_idx, cycles) => {
                    self.page_states.remove(page_idx);
                    self.cycles -= cycles;
                }
                Action::PageWrite(page_idx, cycles, was_loaded) => {
                    if *was_loaded {
                        self.page_states.insert(*page_idx, PageState::Loaded);
                    } else {
                        self.page_states.remove(page_idx);
                    }
                    self.cycles -= cycles;
                }
                Action::Store(addr, data) => {
                    let idx = self.page_table[addr.page_idx() as usize] as usize;
                    self.page_cache[idx].store(*addr, *data);
                }
            }
        }
    }
    ///commit_step 函数的主要功能是清除 pending_actions 列表中的所有挂起操作。这意味着在调用此函数后，所有记录的挂起操作将被移除，准备好接收新的操作。
    pub fn commit_step(&mut self) {
        self.pending_actions.clear();
    }

    pub fn clear(&mut self) {
        self.pending_actions.clear();
        self.page_cache.clear();
        self.page_states.clear();
        self.page_table.fill(INVALID_IDX);
        self.cycles = 0;
    }

    pub fn get_faults(&self) -> PageFaults {
        let mut faults = PageFaults::default();
        // 遍历所有页面状态
        for (page_idx, page_state) in &self.page_states {
            // 将页面索引添加到读取故障集合中
            faults.reads.insert(*page_idx);
            // 如果页面状态为脏页，将页面索引添加到写入故障集合中
            if *page_state == PageState::Dirty {
                faults.writes.insert(*page_idx);
            }
        }
        // 返回页面故障信息
        faults
    }

    pub fn peek_page(&self, page_idx: u32) -> Vec<u8> {
        // 获取页面表中对应页面索引的缓存索引
        let idx = self.page_table[page_idx as usize];
        // 如果缓存索引无效，则从镜像中加载页面
        if idx == INVALID_IDX {
            self.image.load_page(page_idx)
        } else {
            // 否则，从缓存中获取页面数据并返回
            self.page_cache[idx as usize].0.clone()
        }
    }

    fn load_page(&mut self, page_idx: u32) {
        // 记录加载页面的调试信息
        tracing::trace!("load_page: 0x{page_idx:05x}");
        // 从镜像中加载页面数据
        let page = self.image.load_page(page_idx);
        // 更新页面表，将页面索引指向缓存中的新位置
        self.page_table[page_idx as usize] = self.page_cache.len() as u32;
        // 将加载的页面数据添加到缓存中
        self.page_cache.push(Page(page));
        // 更新页面状态为已加载
        self.update(page_idx, PageState::Loaded);
        // 记录页面状态变化
        self.page_changed(page_idx, PageState::Loaded);
    }

    fn update(&mut self, mut page_idx: u32, goal: PageState) {
        // tracing::trace!("update(0x{page_idx:05x}, {goal:?})");
        // 循环更新页面状态，直到根页面
        while page_idx != self.image.info.root_idx {
            let info = &self.image.info;
            // 获取页面条目地址
            let entry_addr = info.get_page_entry_addr(page_idx);
            // 获取父页面索引
            let parent_idx = info.get_page_index(entry_addr);

            // 如果父页面状态存在且小于目标状态，则更新父页面状态
            if let Some(state) = self.page_states.get(&parent_idx) {
                if goal > *state {
                    self.page_changed(parent_idx, goal);
                }
            } else {
                // 否则，从镜像中加载父页面数据并更新状态
                let page = self.image.load_page(parent_idx);
                self.page_table[parent_idx as usize] = self.page_cache.len() as u32;
                self.page_cache.push(Page(page));
                self.page_changed(parent_idx, goal);
            }

            // 更新当前页面索引为父页面索引
            page_idx = parent_idx;
        }
    }

    fn page_changed(&mut self, page_idx: u32, state: PageState) {
        let info = &self.image.info;

        // 计算页面状态变化所需的周期数
        let page_cycles = if page_idx == info.root_idx {
            let num_root_entries = info.num_root_entries as usize;
            cycles_per_page(num_root_entries / 2)
        } else {
            cycles_per_page(BLOCKS_PER_PAGE)
        };

        // 记录页面状态变化的调试信息
        tracing::trace!("page_changed(0x{page_idx:05x}, {state:?}) <= {page_cycles}");
        // 增加总周期数
        self.cycles += page_cycles;

        // 更新页面状态并记录操作
        let old = self.page_states.insert(page_idx, state);
        let action = match state {
            PageState::Loaded => Action::PageRead(page_idx, page_cycles),
            PageState::Dirty => Action::PageWrite(page_idx, page_cycles, old.is_some()),
        };
        self.pending_actions.push(action);
    }
}

impl Page {
    fn load(&self, addr: WordAddr) -> u32 {
        let word_addr = (addr.0 % PAGE_WORDS as u32) as usize;
        let byte_addr = word_addr * WORD_SIZE;
        let mut bytes = [0u8; WORD_SIZE];
        bytes.clone_from_slice(&self.0[byte_addr..byte_addr + WORD_SIZE]);
        //let data = u32::from_le_bytes(bytes);
        // tracing::trace!("load({addr:?}) -> 0x{data:08x}");
        u32::from_le_bytes(bytes)
    }

    fn store(&mut self, addr: WordAddr, data: u32) {
        let word_addr = (addr.0 % PAGE_WORDS as u32) as usize;
        let byte_addr = word_addr * WORD_SIZE;
        // tracing::trace!("store({addr:?}, 0x{data:08x})");
        self.0[byte_addr..byte_addr + WORD_SIZE].clone_from_slice(&data.to_le_bytes());
    }
}
