/*
Copyright 2024-2026 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { describe, it, expect, vi } from "vitest";
import FileView from "../File.vue";

// Mock dependencies
vi.mock("@/composables/useUserSettings", () => ({
  useUserSettings: () => ({
    userSettings: { AIEnabled: false },
  }),
}));

vi.mock("@/stores/app", () => ({
  useAppStore: () => ({
    systemConfig: {},
  }),
}));

vi.mock("@/stores/user", () => ({
  useUserStore: () => ({
    user: { id: 1, display_name: "Test User" },
  }),
}));

vi.mock("@/settings", () => ({
  default: {
    apiServerUrl: "http://mock-api.com",
    apiServerVersion: "v1",
  },
}));

describe("File.vue - Markdown & Security Validation", () => {
  it("identifies valid markdown plain-text files", () => {
    const context = {
      file: {
        display_name: "report.md",
        magic_mime: "text/markdown",
      },
      isTextFormat: true,
    };
    const isMarkdown = FileView.computed.isMarkdownFormat.call(context);
    expect(isMarkdown).toBe(true);
  });

  it("rejects binary files even if named with .md extension", () => {
    const context = {
      file: {
        display_name: "payload.md",
        magic_mime: "application/octet-stream", // Binary executable / unknown data
      },
      isTextFormat: false,
    };
    const isMarkdown = FileView.computed.isMarkdownFormat.call(context);
    expect(isMarkdown).toBe(false);
  });

  it("rejects non-markdown plain text files", () => {
    const context = {
      file: {
        display_name: "data.txt",
        magic_mime: "text/plain",
      },
      isTextFormat: true,
    };
    const isMarkdown = FileView.computed.isMarkdownFormat.call(context);
    expect(isMarkdown).toBe(false);
  });

  it("sanitizes XSS script tags from markdown content", () => {
    const context = {
      fileContent: "# Title\n<script>alert('xss')</script>\n<img src=x onerror=alert(1)>",
    };
    const rendered = FileView.computed.renderedMarkdown.call(context);
    expect(rendered).not.toContain("<script>");
    expect(rendered).not.toContain("onerror");
    expect(rendered).toContain("<h1>Title</h1>");
  });
});
