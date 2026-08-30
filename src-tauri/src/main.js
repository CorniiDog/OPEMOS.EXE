import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { open } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";

const valveDownloadPage =
    "https://store.steampowered.com/steamos/download/?ver=steamdeck";

const $ = (selector) => document.querySelector(selector);

const environmentTitle = $("#environment-title");
const environmentMessage = $("#environment-message");
const environmentDetails = $("#environment-details");
const environmentStatus = $("#environment-status");

const dropZone = $("#drop-zone");
const chooseImage = $("#choose-image");
const openValve = $("#open-valve");

const selectionCard = $("#selection-card");
const selectedName = $("#selected-name");
const selectedPath = $("#selected-path");
const selectionStatus = $("#selection-status");

const buildCard = $("#build-card");
const buildButton = $("#build-button");

const progressWrap = $("#progress-wrap");
const progressBar = $("#progress-bar");
const progressLabel = $("#progress-label");

const resultMessage = $("#result-message");

let currentImage = null;

async function checkBuilderEnvironment() {
    try {
        const environment =
            await invoke("check_builder_environment");

        environmentMessage.textContent =
            environment.message;

        environmentDetails.textContent =
            `${environment.host_os} / ${environment.host_arch}` +
            (
                environment.qemu_version
                    ? ` • ${environment.qemu_version}`
                    : ""
            );

        if (environment.ready) {
            environmentTitle.textContent =
                "Builder ready";

            environmentStatus.textContent =
                "Ready";

            environmentStatus.classList.remove("error");
        } else {
            environmentTitle.textContent =
                "Builder dependency missing";

            environmentStatus.textContent =
                "Not Ready";

            environmentStatus.classList.add("error");
        }
    } catch (error) {
        environmentTitle.textContent =
            "Environment check failed";

        environmentMessage.textContent =
            String(error);

        environmentStatus.textContent =
            "Error";

        environmentStatus.classList.add("error");
    }
}

async function selectImage(path) {
    try {
        const info =
            await invoke(
                "validate_image",
                { path },
            );

        currentImage =
            info.path;

        selectedName.textContent =
            info.name;

        selectedPath.textContent =
            info.path;

        selectionStatus.textContent =
            "Recognized";

        selectionCard.classList.remove("hidden");
        buildCard.classList.remove("hidden");

        resultMessage.textContent =
            "";
    } catch (error) {
        currentImage =
            null;

        selectedName.textContent =
            path
                .split(/[\\/]/)
                .pop();

        selectedPath.textContent =
            path;

        selectionStatus.textContent =
            "Unsupported";

        selectionCard.classList.remove("hidden");
        buildCard.classList.add("hidden");

        resultMessage.textContent =
            String(error);

        resultMessage.className =
            "result-message error";
    }
}

chooseImage.addEventListener(
    "click",
    async () => {
        const selected =
            await open({
                multiple: false,
                directory: false,
                filters: [
                    {
                        name: "SteamOS recovery image",
                        extensions: [
                            "img",
                            "bz2",
                            "gz",
                            "xz",
                        ],
                    },
                ],
            });

        if (typeof selected === "string") {
            await selectImage(selected);
        }
    },
);

openValve.addEventListener(
    "click",
    () => {
        openUrl(valveDownloadPage);
    },
);

buildButton.addEventListener(
    "click",
    async () => {
        if (!currentImage) {
            return;
        }

        buildButton.disabled =
            true;

        progressWrap.classList.remove("hidden");

        resultMessage.textContent =
            "";

        const stages = [
            ["Preparing builder…", 15],
            ["Checking SteamOS image…", 34],
            ["Preparing output…", 53],
            ["Simulating NVIDIA integration…", 72],
            ["Simulating Gamescope integration…", 88],
            ["Finalizing prototype…", 100],
        ];

        for (const [label, percent] of stages) {
            progressLabel.textContent =
                label;

            progressBar.style.width =
                `${percent}%`;

            await new Promise(
                (resolve) => setTimeout(resolve, 300),
            );
        }

        try {
            const output =
                await invoke(
                    "prototype_build",
                    {
                        path: currentImage,
                    },
                );

            resultMessage.textContent =
                `Prototype created: ${output}`;

            resultMessage.className =
                "result-message success";

            progressLabel.textContent =
                "Prototype complete.";
        } catch (error) {
            resultMessage.textContent =
                String(error);

            resultMessage.className =
                "result-message error";
        } finally {
            buildButton.disabled =
                false;
        }
    },
);

const appWindow =
    getCurrentWebviewWindow();

await appWindow.onDragDropEvent(
    async (event) => {
        if (event.payload.type === "over") {
            dropZone.classList.add("dragging");
            return;
        }

        dropZone.classList.remove("dragging");

        if (event.payload.type === "drop") {
            const [path] =
                event.payload.paths;

            if (path) {
                await selectImage(path);
            }
        }
    },
);

await checkBuilderEnvironment();