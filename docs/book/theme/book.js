// #################################################################
// /qompassai/.config/mdbook/theme/book.js
// Qompass AI MDBook Book Theme JS
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// #################################################################
// theme/book.js
// ONTrack mdBook theme enhancements

document.addEventListener("DOMContentLoaded", () => {
  // Add glow class to the menu title for an electric-blue halo
  const title = document.querySelector(".ontrack-menu-title");
  if (title) {
    title.style.textShadow = "0 0 18px rgba(59, 130, 246, 0.8)";
  }

  // Optional: add a tiny hover effect on sidebar logo
  const logo = document.querySelector(".sidebar-logo");
  if (logo) {
    logo.addEventListener("mouseenter", () => {
      logo.querySelector(".sidebar-logo-glow").style.boxShadow =
        "0 0 28px rgba(34, 211, 238, 0.9)";
    });
    logo.addEventListener("mouseleave", () => {
      logo.querySelector(".sidebar-logo-glow").style.boxShadow =
        "0 0 22px rgba(34, 211, 238, 0.55)";
    });
  }
});
