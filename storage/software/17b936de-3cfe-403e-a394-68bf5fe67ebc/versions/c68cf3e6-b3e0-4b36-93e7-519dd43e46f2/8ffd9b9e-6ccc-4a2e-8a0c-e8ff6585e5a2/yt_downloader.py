#!/usr/bin/env python3
"""
YouTube Audio Downloader
========================
Download the audio track from a YouTube video using yt-dlp.

Examples
--------
Download as MP3:
    python youtube_audio.py "https://www.youtube.com/watch?v=VIDEO_ID"

Download as WAV:
    python youtube_audio.py "https://www.youtube.com/watch?v=VIDEO_ID" --format wav

Choose an output directory:
    python youtube_audio.py "https://www.youtube.com/watch?v=VIDEO_ID" --output ~/Music

Download using the best available audio without conversion:
    python youtube_audio.py "URL" --format best

How it works
------------
1. We receive a YouTube URL from the command line.
2. yt-dlp contacts YouTube and retrieves information about the video.
3. We ask yt-dlp for the best available audio stream.
4. yt-dlp downloads that stream.
5. FFmpeg optionally converts the downloaded stream into the requested audio format.
6. The resulting file is saved in the output directory.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yt_dlp


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_OUTPUT_DIRECTORY = "downloads"
DEFAULT_AUDIO_FORMAT = "mp3"


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    argparse gives us a clean interface instead of hard-coding things such as
    the URL and output directory inside the program.
    """
    parser = argparse.ArgumentParser(
        description="Download audio from a YouTube video."
    )
    parser.add_argument(
        "url",
        help="URL of the YouTube video",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT_DIRECTORY,
        help=f"Directory where the audio will be saved "
        f"(default: {DEFAULT_OUTPUT_DIRECTORY})",
    )
    parser.add_argument(
        "-f",
        "--format",
        default=DEFAULT_AUDIO_FORMAT,
        choices=[
            "mp3",
            "m4a",
            "opus",
            "wav",
            "flac",
            "best",
        ],
        help="Output audio format (default: mp3)",
    )
    parser.add_argument(
        "--quality",
        default="192",
        help=(
            "Audio bitrate for formats such as MP3 "
            "(default: 192 kbps)"
        ),
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Progress reporting
# ---------------------------------------------------------------------------

def progress_hook(data: dict) -> None:
    """Receive download progress information from yt-dlp.

    yt-dlp calls this function repeatedly while downloading.
    `status` tells us what stage the downloader is currently in.

    Common values include:
        downloading
        finished
        error
    """
    status = data.get("status")

    if status == "downloading":
        downloaded = data.get("_percent_str", "?")
        speed = data.get("_speed_str", "?")
        eta = data.get("_eta_str", "?")
        print(
            f"\rDownloading: {downloaded} "
            f"| Speed: {speed} "
            f"| ETA: {eta}",
            end="",
            flush=True,
        )
    elif status == "finished":
        print("\nDownload complete. Processing audio...")


# ---------------------------------------------------------------------------
# Downloader
# ---------------------------------------------------------------------------

def download_audio(
    url: str,
    output_directory: str,
    audio_format: str,
    quality: str,
) -> None:
    """Download and optionally convert a YouTube video's audio.

    Parameters
    ----------
    url:
        The YouTube video URL.
    output_directory:
        Directory where the resulting file should be stored.
    audio_format:
        Desired output format.
    quality:
        Desired audio bitrate where applicable.
    """
    # Expand things such as "~" in paths.
    #
    # For example:
    #
    #   ~/Music
    #
    # becomes:
    #
    #   /home/user/Music
    output_path = Path(output_directory).expanduser()

    # Create the directory if it does not already exist.
    #
    # parents=True:
    #   Create missing parent directories too.
    #
    # exist_ok=True:
    #   Don't raise an error if the directory already exists.
    output_path.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------
    # yt-dlp configuration
    # ---------------------------------------------------------------

    options = {
        # "bestaudio/best" means:
        #
        # 1. Prefer the best audio-only stream.
        # 2. Fall back to the best available format if necessary.
        #
        # We don't need the video stream because our goal is audio.
        "format": "bestaudio/best",

        # Output filename template.
        #
        # %(title)s is replaced with the video's title.
        # %(ext)s is replaced with the downloaded file's extension.
        #
        # Example:
        #
        #   downloads/My Video Title.webm
        "outtmpl": str(output_path / "%(title)s.%(ext)s"),

        # Tell yt-dlp to display download progress.
        "progress_hooks": [progress_hook],

        # Avoid unnecessary console output.
        "quiet": True,

        # Still show warnings and errors.
        "no_warnings": False,
    }

    # ---------------------------------------------------------------
    # Post-processing
    # ---------------------------------------------------------------

    if audio_format != "best":
        """
        FFmpeg is used here.

        yt-dlp itself downloads the media stream, but FFmpeg performs
        operations such as converting WebM/Opus audio into MP3.

        For example:

            YouTube
               |
               v
            Opus/WebM stream
               |
               v
            FFmpeg
               |
               v
            MP3 file
        """
        options["postprocessors"] = [
            {
                "key": "FFmpegExtractAudio",
                # Desired output format.
                "preferredcodec": audio_format,
                # 0 means don't explicitly force a quality level here.
                # For lossy formats we handle bitrate separately below.
                "preferredquality": quality,
            }
        ]

    # ---------------------------------------------------------------
    # Start download
    # ---------------------------------------------------------------

    try:
        # YoutubeDL acts as the main yt-dlp controller.
        #
        # Using it as a context manager ensures resources are properly
        # cleaned up after the operation.
        with yt_dlp.YoutubeDL(options) as downloader:
            # extract_info() does the actual work.
            #
            # download=True tells yt-dlp to download the media instead
            # of merely retrieving metadata.
            downloader.download([url])

    except yt_dlp.utils.DownloadError as exc:
        """
        yt-dlp raises DownloadError for many download-related problems.

        Examples:
            - Invalid URL
            - Video unavailable
            - Network failure
            - Geo restriction
            - Missing FFmpeg
            - YouTube changing something that yt-dlp needs to handle
        """
        print(f"\nDownload failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    except KeyboardInterrupt:
        """
        Ctrl+C reaches this block.

        We don't want a traceback when the user intentionally cancels
        the download.
        """
        print("\nDownload cancelled.")
        raise SystemExit(130)


# ---------------------------------------------------------------------------
# Program entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Application entry point.

    Keeping the CLI logic inside main() makes this file easier to
    reuse as a Python module later.
    """
    args = parse_arguments()

    download_audio(
        url=args.url,
        output_directory=args.output,
        audio_format=args.format,
        quality=args.quality,
    )


if __name__ == "__main__":
    main()