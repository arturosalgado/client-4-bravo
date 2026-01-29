/**
 * Custom Fingerprint Service
 * Generates a device fingerprint hash from common browser attributes
 */

const FingerprintService = (function() {
    'use strict';

    /**
     * Get the platform type from user agent
     * @returns {string} Platform type (android, ios, macos, windows, linux, web)
     */
    function getPlatformType() {
        const ua = navigator.userAgent.toLowerCase();
        if (/android/.test(ua)) return 'android';
        if (/iphone|ipad|ipod/.test(ua)) return 'ios';
        if (/macintosh|mac os/.test(ua)) return 'macos';
        if (/windows/.test(ua)) return 'windows';
        if (/linux/.test(ua)) return 'linux';
        return 'web';
    }

    /**
     * Get the OS version from user agent
     * @returns {string} OS version or 'unknown'
     */
    function getOSVersion() {
        const ua = navigator.userAgent;
        let match;

        if ((match = ua.match(/Android\s([\d.]+)/))) return match[1];
        if ((match = ua.match(/OS\s([\d_]+)/))) return match[1].replace(/_/g, '.');
        if ((match = ua.match(/Windows NT\s([\d.]+)/))) return match[1];
        if ((match = ua.match(/Mac OS X\s([\d_]+)/))) return match[1].replace(/_/g, '.');

        return 'unknown';
    }

    /**
     * Collect all fingerprint attributes from the browser
     * @returns {Object} Object containing all fingerprint attributes
     */
    function collectAttributes() {
        return {
            devicePlatform: getPlatformType(),
            osVersion: getOSVersion(),
            screenWidth: screen.width,
            screenHeight: screen.height,
            pixelRatio: window.devicePixelRatio || 1,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language
        };
    }

    /**
     * Simple hash function (fallback for non-secure contexts)
     * @param {string} str - String to hash
     * @returns {string} Hex-encoded hash
     */
    function simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        // Create a longer hash by combining multiple passes
        const hash1 = Math.abs(hash).toString(16).padStart(8, '0');

        let hash2 = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash2 = ((hash2 << 7) - hash2) + char + i;
            hash2 = hash2 & hash2;
        }
        const hash2Str = Math.abs(hash2).toString(16).padStart(8, '0');

        let hash3 = 0;
        for (let i = str.length - 1; i >= 0; i--) {
            const char = str.charCodeAt(i);
            hash3 = ((hash3 << 3) - hash3) + char * (i + 1);
            hash3 = hash3 & hash3;
        }
        const hash3Str = Math.abs(hash3).toString(16).padStart(8, '0');

        let hash4 = 5381;
        for (let i = 0; i < str.length; i++) {
            hash4 = ((hash4 << 5) + hash4) + str.charCodeAt(i);
            hash4 = hash4 & hash4;
        }
        const hash4Str = Math.abs(hash4).toString(16).padStart(8, '0');

        return hash1 + hash2Str + hash3Str + hash4Str;
    }

    /**
     * Create SHA-256 hash from string (with fallback for non-secure contexts)
     * @param {string} str - String to hash
     * @returns {Promise<string>} Hex-encoded hash
     */
    async function sha256(str) {
        // Check if crypto.subtle is available (requires secure context)
        if (window.crypto && window.crypto.subtle) {
            try {
                const encoder = new TextEncoder();
                const buffer = await crypto.subtle.digest('SHA-256', encoder.encode(str));
                return Array.from(new Uint8Array(buffer))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            } catch (e) {
                console.warn('[Fingerprint] crypto.subtle failed, using fallback hash');
                return simpleHash(str);
            }
        }
        // Fallback for non-secure contexts (file://, http://)
        console.warn('[Fingerprint] crypto.subtle not available, using fallback hash');
        return simpleHash(str);
    }

    /**
     * Generate fingerprint hash from provided parameters
     * @param {Object} params - Fingerprint parameters
     * @param {string} params.devicePlatform - Device platform (android, ios, macos, windows, linux, web)
     * @param {string} params.osVersion - Operating system version
     * @param {number} params.screenWidth - Screen width in pixels
     * @param {number} params.screenHeight - Screen height in pixels
     * @param {number} params.pixelRatio - Device pixel ratio
     * @param {string} params.timezone - Timezone (e.g., 'America/New_York')
     * @param {string} params.language - Language/locale (e.g., 'en-US')
     * @param {string} [params.platform='admin'] - Application platform ('admin' or 'shell')
     * @returns {Promise<string>} SHA-256 hash of the fingerprint
     */
    async function generateHash({
        devicePlatform,
        osVersion,
        screenWidth,
        screenHeight,
        pixelRatio,
        timezone,
        language,
        platform = 'admin'
    }) {
        // Validate platform parameter
        if (platform !== 'admin' && platform !== 'shell') {
            console.warn('[Fingerprint] Invalid platform value, defaulting to "admin"');
            platform = 'admin';
        }

        // Create consistent string for hashing
        const fingerprintString = [
            devicePlatform,
            osVersion,
            screenWidth,
            screenHeight,
            pixelRatio,
            timezone,
            language,
            platform
        ].join('|');

        return await sha256(fingerprintString);
    }

    /**
     * Get fingerprint hash using auto-detected browser attributes
     * @param {string} [platform='admin'] - Application platform ('admin' or 'shell')
     * @returns {Promise<Object>} Object containing attributes and hash
     */
    async function getFingerprint(platform = 'admin') {
        const attributes = collectAttributes();
        const hash = await generateHash({
            ...attributes,
            platform
        });

        return {
            attributes: {
                ...attributes,
                platform
            },
            hash
        };
    }

    /**
     * Get only the fingerprint hash using auto-detected browser attributes
     * @param {string} [platform='admin'] - Application platform ('admin' or 'shell')
     * @returns {Promise<string>} SHA-256 hash
     */
    async function getHash(platform = 'admin') {
        const { hash } = await getFingerprint(platform);
        return hash;
    }

    // Public API
    return {
        collectAttributes,
        generateHash,
        getFingerprint,
        getHash
    };
})();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FingerprintService;
}
