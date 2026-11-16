import { defaultKind } from "./platform";
import "./style.css";
import { api } from "./api";
import { byId } from "./dom";
import { initRunbar } from "./runbar";
import { initSidebar } from "./sidebar";
import { emit, loadState, state, subscribe, type Mode } from "./state";
import { initTerminals, openSession } from "./terminals";
import { initStudio } from "./studio";
import { initToolbar } from "./toolbar";

const NARROW = window.matchMedia("(max-width: 800px)").matches;

function applyMode(mode: Mode, persist: boolean): void {
  state.mode = mode;
  document.body.dataset.mode = mode;
  if (mode === "pro") {
    state.sidebarOpen = false; // الوضع الاحترافي: الطرفية أولاً
  } else {
    state.sidebarOpen = !NARROW; // على الشاشة الضيقة (هاتف) القائمة تغطي الشاشة فتبدأ مطويّة
    state.tab = mode === "smart" ? "smart" : "commands";
  }
  if (persist) void api.setSetting("mode", mode).catch(() => {});
  emit();
}

async function main(): Promise<void> {
  await loadState();

  const modeBtns = document.querySelectorAll<HTMLButtonElement>("[data-mode-btn]");
  for (const b of modeBtns) {
    b.addEventListener("click", () => applyMode(b.dataset.modeBtn as Mode, true));
  }
  subscribe(() => {
    for (const b of modeBtns) b.classList.toggle("active", b.dataset.modeBtn === state.mode);
  });

  initToolbar();
  initSidebar();
  initRunbar();
  initStudio();
  await initTerminals();

  applyMode(state.mode, false);
  byId("status").textContent = "جاهز";

  // أول جلسة تُفتح تلقائياً لتكون التجربة مباشرة
  await openSession(defaultKind());
}

void main();
