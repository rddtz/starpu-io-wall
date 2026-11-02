# IOTRACE2 analysis: split the .rsf@ bytes written to disk into intervals
# defined by the StarFletcher anchors, and plot the StarVZ timeline with the
# disk I/O on the same time axis.
#
# Usage: Rscript iotrace2_analyze.R RUN_DIR OUT_DIR CONFIG
#   RUN_DIR: output of iotrace2_run.sh, with fxt/ already processed by StarVZ
#   OUT_DIR: new directory for summary.csv and timeline.{pdf,png}
#   CONFIG:  StarVZ yaml (star-fletcher/config.yaml); its active panels are
#            drawn above the I/O panels, with the time limits widened to
#            include the writeback after exit
#
# Time base: StarVZ time (ms). FxT and iotrace both use CLOCK_MONOTONIC, so
# anchor 1 (start), present in stdout (ns) and in the FxT user events (StarVZ
# ms), gives the offset. Anchor 2 checks it.

suppressMessages({
  library(starvz)
  library(arrow)
  library(dplyr)
  library(readr)
  library(ggplot2)
  library(patchwork)
})

args <- commandArgs(trailingOnly = TRUE)
stopifnot(length(args) == 3)
run_dir <- args[1]
out_dir <- args[2]
config_file <- args[3]
stopifnot(!dir.exists(out_dir))
dir.create(out_dir, recursive = TRUE)

# ---- load -------------------------------------------------------------------
env <- read_lines(file.path(run_dir, "env.txt"))
inode <- as.numeric(sub(".*inode=([0-9]+).*", "\\1", grep("^inode=", env, value = TRUE)))
file_size <- as.numeric(sub(".*size=([0-9]+).*", "\\1", grep("^inode=", env, value = TRUE)))

anchors <- read_lines(file.path(run_dir, "sf.log")) %>%
  grep("^ANCHOR ", ., value = TRUE) %>%
  strsplit(" ") %>%
  lapply(function(x) tibble(name = x[2], code = as.integer(x[3]), mono_ns = as.numeric(x[4]))) %>%
  bind_rows()

io <- read_csv(file.path(run_dir, "io.csv"), show_col_types = FALSE,
               col_types = cols(ts_ns = col_double(), sector = col_double(),
                                bytes = col_double(), inode = col_double(),
                                .default = col_character()))

fxt_events <- read_parquet(file.path(run_dir, "fxt", "events.parquet")) %>%
  filter(Type == "user event type") %>%
  transmute(code = as.integer(as.character(Value)), starvz_ms = Start)

# ---- clock alignment ----------------------------------------------------------
al <- inner_join(anchors, fxt_events, by = "code")
stopifnot(1 %in% al$code)
ref <- al %>% filter(code == 1)
to_ms <- function(ns) (ns - ref$mono_ns) / 1e6 + ref$starvz_ms
al <- al %>% mutate(err_us = (to_ms(mono_ns) - starvz_ms) * 1e3)
anchors <- anchors %>% mutate(t_ms = to_ms(mono_ns))
io <- io %>% mutate(t_ms = to_ms(ts_ns))

a <- setNames(anchors$t_ms, anchors$name)

# ---- interval split -------------------------------------------------------------
interval_of <- function(t) {
  case_when(t < a["start"] ~ "0_before_start",
            t < a["tasks_done"] ~ "1_start_to_tasks_done",
            t <= a["exit"] ~ "2_tasks_done_to_exit",
            TRUE ~ "3_after_exit")
}

file_wb <- io %>%
  filter(event == "wb_inode", inode == !!inode) %>%
  mutate(interval = interval_of(t_ms))

disk_w <- io %>%
  filter(event == "rq_complete", op == "W") %>%
  mutate(interval = interval_of(t_ms),
         who = ifelse(grepl("^kworker", comm), "kworker", comm))

sf_pid <- suppressWarnings(as.numeric(sub("^sf_pid=", "", grep("^sf_pid=", env, value = TRUE))))

# ---- who submitted each write (iotrace with bio_queue, IOTRACE3) ---------------
# block_bio_queue runs in the submitter context, so unlike rq_issue it never
# shows swapper (irq) or kblockd (deferred dispatch).
submitter_of <- function(pid, comm) {
  case_when(length(sf_pid) == 1 & as.numeric(pid) == sf_pid ~ "StarFletcher",
            grepl("^kworker/u", comm) ~ "flusher (kworker/u*)",
            grepl("^jbd2/", comm) ~ "jbd2 (ext4 journal)",
            TRUE ~ "other")
}
has_bio <- any(io$event == "bio_queue")
if (has_bio) {
  bio_w <- io %>%
    filter(event == "bio_queue", op == "W") %>%
    mutate(interval = interval_of(t_ms), who = submitter_of(pid, comm))
  by_comm <- bio_w %>%
    group_by(interval, who, dev, pid, comm) %>%
    summarise(bytes = sum(bytes), bios = n(), .groups = "drop") %>%
    arrange(interval, desc(bytes))
  write_csv(by_comm, file.path(out_dir, "disk_submitted_by_comm.csv"))
  cat("disk W submitted (bio_queue), by submitter:\n")
  print(bio_w %>% group_by(interval, who) %>%
          summarise(bytes = sum(bytes), bios = n(), .groups = "drop"))
  cat("disk W submitted by processes other than StarFletcher and the kernel",
      "threads (flusher, jbd2), by comm:\n")
  print(by_comm %>% filter(who == "other") %>% group_by(comm) %>%
          summarise(bytes = sum(bytes), bios = sum(bios), .groups = "drop") %>%
          arrange(desc(bytes)), n = Inf)
}
if (any(io$event == "syscall")) {
  sc <- io %>%
    filter(event == "syscall") %>%
    mutate(interval = interval_of(t_ms), dur_ms = as.numeric(aux2) / 1e6) %>%
    group_by(interval, pid, comm, op, dev, inode) %>%
    summarise(calls = n(), bytes = sum(bytes), dur_ms_sum = sum(dur_ms),
              dur_ms_max = max(dur_ms), .groups = "drop") %>%
    arrange(interval, desc(bytes))
  write_csv(sc, file.path(out_dir, "syscalls.csv"))
  cat("write/sync syscalls on disk files (and msync/munmap >= 1 MiB):\n")
  print(sc, n = 40)
}
if (any(io$event == "bdp")) {
  bdp <- io %>%
    filter(event == "bdp") %>%
    mutate(interval = interval_of(t_ms), pause_j = as.numeric(aux2)) %>%
    group_by(interval, pid, comm) %>%
    summarise(calls = n(), sleeps = sum(pause_j > 0),
              pause_jiffies = sum(pmax(pause_j, 0)),
              max_dirty_bytes = max(bytes), dirty_thresh_bytes = max(as.numeric(aux1)),
              .groups = "drop")
  write_csv(bdp, file.path(out_dir, "dirty_throttling.csv"))
  cat("balance_dirty_pages (pause in jiffies; HZ in env.txt or the notes):\n")
  print(bdp, n = 40)
}

intervals <- c("0_before_start", "1_start_to_tasks_done",
               "2_tasks_done_to_exit", "3_after_exit")
summary <- tibble(interval = intervals) %>%
  left_join(file_wb %>% group_by(interval) %>%
              summarise(file_wb_bytes = sum(bytes), file_wb_calls = n()),
            by = "interval") %>%
  left_join(disk_w %>% group_by(interval) %>%
              summarise(disk_w_bytes = sum(bytes), disk_w_requests = n()),
            by = "interval") %>%
  mutate(across(-interval, ~ coalesce(.x, 0)),
         file_wb_pct = 100 * file_wb_bytes / file_size)

write_csv(summary, file.path(out_dir, "summary.csv"))
write_csv(al, file.path(out_dir, "clock_alignment.csv"))
write_csv(disk_w %>% group_by(interval, who) %>% summarise(bytes = sum(bytes), .groups = "drop"),
          file.path(out_dir, "disk_writes_by_comm.csv"))

cat("file inode", inode, "size", file_size, "\n")
cat("anchors (StarVZ ms):\n"); print(anchors %>% select(name, t_ms))
cat("clock alignment error (us):\n"); print(al %>% select(name, err_us))
print(summary)
cat("file writeback first/last after exit (s):",
    (min(file_wb$t_ms) - a["exit"]) / 1e3, (max(file_wb$t_ms) - a["exit"]) / 1e3, "\n")

# ---- who dirtied the file, and why writeback ran (iotrace with dirty/wb_start)
if (any(io$event == "dirty")) {
  dirtiers <- io %>%
    filter(event == "dirty", inode == !!inode) %>%
    mutate(interval = interval_of(t_ms)) %>%
    group_by(pid, comm, interval) %>%
    summarise(bytes = sum(bytes), pages = n(), .groups = "drop") %>%
    mutate(is_sf = length(sf_pid) == 1 & as.numeric(pid) == sf_pid,
           pct_of_file = 100 * bytes / file_size)
  write_csv(dirtiers, file.path(out_dir, "file_dirtied_by.csv"))
  cat("pages of the file dirtied, by process (sf_pid =", sf_pid, "):\n")
  print(dirtiers)
}
if (any(io$event == "wb_start")) {
  wb_passes <- io %>%
    filter(event == "wb_start") %>%
    transmute(pass_ms = t_ms, t_after_exit_s = (t_ms - a["exit"]) / 1e3,
              reason = op, requested_bytes = bytes, pid, comm)
  write_csv(wb_passes, file.path(out_dir, "writeback_passes.csv"))
  # pass that was running on the same flusher thread when each file
  # writeback call happened (several flusher threads run at the same time)
  file_wb_reason <- file_wb %>%
    left_join(wb_passes %>% select(pid, pass_ms, reason),
              by = join_by(pid, closest(t_ms >= pass_ms))) %>%
    mutate(reason = coalesce(reason, "none")) %>%
    group_by(reason) %>%
    summarise(bytes = sum(bytes), calls = n(),
              first_after_exit_s = (min(t_ms) - a["exit"]) / 1e3, .groups = "drop")
  write_csv(file_wb_reason, file.path(out_dir, "file_writeback_by_reason.csv"))
  cat("file writeback by triggering reason:\n")
  print(file_wb_reason)
}

# ---- figure ---------------------------------------------------------------------
x_max <- max(file_wb$t_ms, a["exit"]) + 500
x_lim <- c(min(0, a["start"]), x_max)

vlines <- anchors %>% filter(name != "io_closed")
vline_layer <- list(
  geom_vline(data = vlines, aes(xintercept = t_ms), linetype = "dashed", colour = "grey30"),
  coord_cartesian(xlim = x_lim)
)

data <- starvz_read(file.path(run_dir, "fxt"), config_file = config_file,
                    selective = FALSE)
data$config <- modifyList(starvz:::starvz_default_config(), data$config)
data$config$limits$start <- x_lim[1]
data$config$limits$end <- x_lim[2]
p_starvz <- starvz_assemble(starvz_plot_list(data), config = data$config)

bin_ms <- 100
# with bio_queue: colour by submitter, time = submission; else rq_complete
rate_src <- if (has_bio) bio_w else disk_w
rate_lab <- if (has_bio) "disk W submitted\n(MiB/s)" else "disk W\n(MiB/s)"
disk_rate <- rate_src %>%
  filter(t_ms >= x_lim[1], t_ms <= x_lim[2]) %>%
  mutate(bin = floor(t_ms / bin_ms) * bin_ms) %>%
  group_by(bin, who) %>%
  summarise(mb_s = sum(bytes) / 1048576 / (bin_ms / 1e3), .groups = "drop")

p_rate <- ggplot(disk_rate, aes(x = bin, y = mb_s, fill = who)) +
  geom_col(width = bin_ms, position = "stack") +
  vline_layer +
  labs(x = NULL, y = rate_lab, fill = NULL) +
  theme_bw() + theme(legend.position = "top")

cum <- file_wb %>% arrange(t_ms) %>% mutate(mib = cumsum(bytes) / 1048576)
p_cum <- ggplot(cum, aes(x = t_ms, y = mib)) +
  geom_step() +
  geom_hline(yintercept = file_size / 1048576, linetype = "dotted") +
  vline_layer +
  annotate("text", x = vlines$t_ms, y = file_size / 1048576, label = vlines$name,
           angle = 90, vjust = -0.4, hjust = 1, size = 3) +
  labs(x = "time (ms, StarVZ base)", y = ".rsf@ written\nback (MiB)") +
  theme_bw()

# "/" appends to the StarVZ patchwork (same x alignment), so the heights are
# the StarVZ ones plus one per I/O panel
h_starvz <- unlist(p_starvz$patches$layout$heights)
fig <- p_starvz / p_rate / p_cum +
  plot_layout(heights = c(h_starvz, rep(sum(h_starvz) * 0.22, 2)))
ggsave(file.path(out_dir, "timeline.pdf"), fig, width = 10, height = 10)
ggsave(file.path(out_dir, "timeline.png"), fig, width = 10, height = 10, dpi = 150)

# compact figure: only the workers panel (StarVZ st) and the disk writes
cfg_top <- data$config
for (k in names(cfg_top)) {
  if (k != "st" && is.list(cfg_top[[k]]) && !is.null(cfg_top[[k]]$active)) {
    cfg_top[[k]]$active <- FALSE
  }
}
data_top <- data
data_top$config <- cfg_top
p_top <- starvz_assemble(starvz_plot_list(data_top), config = cfg_top)
h_top <- unlist(p_top$patches$layout$heights)
p_rate_lab <- p_rate +
  annotate("text", x = vlines$t_ms, y = Inf, label = vlines$name,
           angle = 90, vjust = -0.4, hjust = 1.1, size = 3) +
  labs(x = "time (ms, StarVZ base)")
fig_top <- p_top / p_rate_lab + plot_layout(heights = c(h_top, sum(h_top) * 0.6))
ggsave(file.path(out_dir, "timeline_workers_write.pdf"), fig_top, width = 10, height = 6)
ggsave(file.path(out_dir, "timeline_workers_write.png"), fig_top, width = 10, height = 6, dpi = 150)
cat("written:", out_dir, "\n")
