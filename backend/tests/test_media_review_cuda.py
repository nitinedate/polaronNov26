"""Image/video observations keep eight shard workers and add one CUDA reader."""

import threading

from app.services import forensic_media_review as review


def test_media_review_defaults_to_eight_workers(monkeypatch):
    monkeypatch.delenv("MEDIA_REVIEW_WORKERS", raising=False)
    monkeypatch.setattr("os.cpu_count", lambda: 10)
    assert review.media_review_workers() == 8
    monkeypatch.setattr("os.cpu_count", lambda: 24)
    assert review.media_review_workers() == 16


def test_media_cuda_stays_on_unless_cpu_is_requested(monkeypatch):
    monkeypatch.delenv("FORENSIC_MEDIA_REVIEW_CUDA", raising=False)
    assert review.media_cuda_requested() is True
    monkeypatch.setenv("FORENSIC_MEDIA_REVIEW_CUDA", "off")
    assert review.media_cuda_requested() is False


def test_shard_threads_do_not_inherit_the_cuda_reader():
    token = review._frame_reader.set(lambda _blob: ("parent", 1.0))
    seen = []

    def worker():
        seen.append(review._frame_reader.get())

    try:
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
    finally:
        review._frame_reader.reset(token)
    assert seen == [None]


def test_shard_thread_uses_the_reader_it_sets(monkeypatch):
    monkeypatch.setattr(review, "_tesseract_frame", lambda _blob: {"ocr_engine": "tesseract"})
    seen = []

    def worker():
        review._frame_reader.set(lambda _blob: ("plate", 0.9))
        seen.append(review._observe_frame(b"frame")["ocr_engine"])

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    assert seen == ["cuda"]


def test_observe_frame_uses_the_cuda_reader(monkeypatch):
    monkeypatch.setattr(review, "_tesseract_frame", lambda _blob: {"ocr_engine": "tesseract"})
    token = review._frame_reader.set(lambda _blob: ("plate 42", 0.91))
    try:
        observed = review._observe_frame(b"frame")
    finally:
        review._frame_reader.reset(token)
    assert observed["ocr_engine"] == "cuda"
    assert observed["model"] == "glm-ocr"
    assert observed["description"] == "plate 42"


def test_observe_frame_uses_tesseract_when_cuda_fails(monkeypatch):
    monkeypatch.setattr(
        review,
        "_tesseract_frame",
        lambda _blob: {"description": "cpu text", "ocr_engine": "tesseract", "model": "tesseract"},
    )

    def fail(_blob):
        raise RuntimeError("cuda busy")

    token = review._frame_reader.set(fail)
    try:
        observed = review._observe_frame(b"frame")
    finally:
        review._frame_reader.reset(token)
    assert observed["ocr_engine"] == "tesseract"
    assert observed["description"] == "cpu text"


def test_cuda_batch_returns_each_frame_in_order(monkeypatch):
    class _Image:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def convert(self, _mode):
            return self

        def thumbnail(self, _size):
            return None

        def copy(self):
            return "frame"

    class _ImageModule:
        @staticmethod
        def open(_handle):
            return _Image()

    class _Ops:
        @staticmethod
        def exif_transpose(image):
            return image

    monkeypatch.setitem(__import__("sys").modules, "PIL", type("PIL", (), {"Image": _ImageModule, "ImageOps": _Ops}))
    monkeypatch.setitem(__import__("sys").modules, "PIL.Image", _ImageModule)
    monkeypatch.setitem(__import__("sys").modules, "PIL.ImageOps", _Ops)

    batcher = review._CudaObservationBatcher()
    import queue

    boxes = [queue.Queue() for _ in range(3)]
    payloads = [b"one", b"bad", b"three"]

    real_open = _ImageModule.open

    def open_image(handle):
        if handle.read(1) == b"x":
            raise OSError("not an image")
        return real_open(handle)

    _ImageModule.open = staticmethod(open_image)
    batch = [(payload, box) for payload, box in zip(payloads, boxes)]
    batch[1] = (b"x", boxes[1])

    def ocr(images, *, prompt):
        assert prompt == review._CUDA_PROMPT
        assert images == ["frame", "frame"]
        return [("first", 0.8), ("third", 0.4)]

    batcher._infer(batch, ocr)
    assert boxes[0].get_nowait() == ("first", 0.8)
    assert isinstance(boxes[1].get_nowait()[0], OSError)
    assert boxes[2].get_nowait() == ("third", 0.4)
