from pydantic import BaseModel, Field


class JobCreate(BaseModel):
    type: str = "host_disk"
    domain_pack: str | None = "forensic"
    case_id: str | None = None
    mobile_os: str | None = None
    source_type: str | None = None
    acquisition_mode: str | None = None
    legal_authority_acknowledged: bool = False
    evidence_path: str | None = None


class ClientSourceBody(BaseModel):
    """Connect a folder on the examiner's own computer (Client Evidence Agent share).

    The browser obtains ``share_id``/``token`` from the local agent and hands them
    to the server, which must reach the agent itself over the LAN. Evidence stays
    on the client computer; nothing is uploaded.
    """

    share_id: str = Field(min_length=10, max_length=80, pattern=r"^ce[0-9a-f]{16,64}$")
    token: str = Field(min_length=24, max_length=256)
    port: int = Field(default=9877, ge=1, le=65535)
    addresses: list[str] = Field(default_factory=list, max_length=16)
    hostname: str = Field(default="", max_length=253)
    client_root: str = Field(default="", max_length=1024)
    file_count: int = Field(default=0, ge=0)
    total_bytes: int = Field(default=0, ge=0)
    manifest_sha256: str = Field(default="", max_length=64)
    source_type: str = "disk"
    # Optional examiner override when the server needs a specific address/port,
    # e.g. "http://10.20.30.40:9877" behind NAT or a second network adapter.
    agent_url: str | None = Field(default=None, max_length=200)
    # False for the 2nd..nth directory of one multi-directory selection.
    replace_existing: bool = True
    # The agent also keeps an outbound connection to this server for the share
    # (works when the server cannot reach the PC, e.g. at home behind a router).
    relay: bool = False


class IngestPathBody(BaseModel):
    path: str | None = None
    source_type: str = "disk"
    selected_names: list[str] | None = None
    auto_process: bool = False
    drive: str = ""
    browse_path: str = ""
    # When true, skip folder listing (client already called list-folder).
    skip_folder_list: bool = False
    # standard | deep.  None = keep the profile already stored on the job (set by
    # PUT /jobs/{id}/processing-profile when the examiner picks the mode); a
    # default here used to overwrite a stored "deep" choice with "standard".
    processing_profile: str | None = None


class ProcessingProfileBody(BaseModel):
    processing_profile: str  # standard | deep


class ListFolderBody(BaseModel):
    path: str | None = None
    drive: str = ""
    browse_path: str = ""


class ResolveFolderBody(BaseModel):
    filenames: list[str] | None = None
    files: list[str] | None = None
    folder_hint: str | None = None
    folder: str | None = None
    relative_path: str | None = None
    relative_paths: list[str] | None = None
    paths: list[str] | None = None
    # Optional exact byte sizes keyed by filename. Browser-selected E01 sets use
    # this to prove a server-drive match before deciding whether any upload is
    # necessary. Filename-only matches are unsafe across forensic cases.
    file_sizes: dict[str, int] | None = None
