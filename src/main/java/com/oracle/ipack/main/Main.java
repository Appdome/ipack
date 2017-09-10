/*
 * Copyright (c) 2011, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.oracle.ipack.main;

import com.oracle.ipack.packer.Packer;
import com.oracle.ipack.signer.Signer;
import com.oracle.ipack.util.ResourceDescriptor;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.InvalidNameException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

public final class Main {
    private static final String USAGE =
            "Usage:\n"
            + "\n"
            + " ipack [ <archive> ] <signing opts> <application opts>"
                    + " [ <application opts> ... ]\n"
            + "\n"
            + "Signing options:\n"
            + "\n"
            + " -keystore <keystore>   "
                  + "keystore to use for signing\n"
            + " -storepass <password>  "
                  + "keystore password\n"
            + " -alias <alias>         "
                  + "alias for the signing certificate chain and\n"
            + "                        the associated private key\n"
            + " -keypass <password>    "
                  + "password for the private key\n"
            + "\n"
            + "Application options:\n"
            + "\n"
            + " -basedir <directory>   "
                  + "base directory from which to derive relative paths\n"
            + " -appdir <directory>    "
                  + "directory with the application executable and resources\n"
            + " -appname <file>        "
                  + "name of the application executable\n"
            + " -appid <id>            "
                  + "application identifier\n"
            + " -teamid <id>           "
                  + "team identifier\n"
            + " -entitlements <file>   "
                  + "path to entitlements plist\n"
            + " [-resources_hash <SHA1 Hash>] "
                  + "SHA1 Hash of CodeResources file\n"
            + " [-info_plist_hash <SHA1 Hash>] "
                  + "SHA1 Hash of Info.plist file\n"
            + " [-resources_256_hash <SHA256 Hash>] "
                  + "SHA256 Hash of CodeResources file\n"
            + " [-info_plist_256_hash <SHA256 Hash>] "
                  + "SHA256 Hash of Info.plist file\n"
            + " [--no_bundle]          "
                  + "specifies standalone executable (No code resources or Info.plist)\n"
            + " [--in_place]           "
                  + "sign the executable in-place\n"
            + "\n"
            + "Example:\n"
            + "\n"
            + " ipack MyApplication.ipa -keystore ipack.ks"
                  + " -storepass keystorepwd\n"
            + "                        "
                  + " -alias mycert -keypass keypwd\n"
            + "                        "
                  + " -basedir mysources/MyApplication/dist\n"
            + "                        "
                  + " -appdir Payload/MyApplication.app\n"
            + "                        "
                  + " -appname MyApplication\n"
            + "                        "
                  + " -appid com.myorg.MyApplication\n"
            + "                        "
                  + " -teamid ABCDE12345\n"
            + "                        "
                  + " -entitlements /path/to/entitlements.plist\n"
            + "                        "
                  + " [-resources_hash A1FF60E3B3184CF229C655D56227CCF7066F6D51]\n"
            + "                        "
                  + " [-info_plist_hash A1FF60E3B3184CF229C655D56227CCF7066F6D51]\n"
            + "                        "
                  + " [-resources_256_hash A1FF60E3B3184CF229C655D56227CCF7066F6D51A1FF60E3B3184CF229C655D5]\n"
            + "                        "
                  + " [-info_plist_256_hash A1FF60E3B3184CF229C655D56227CCF7066F6D51A1FF60E3B3184CF229C655D5]\n"
            + "                        "
                  + " [--no_bundle]\n"
            + "                        "
                  + " [--in_place]";

    private Main() {
    }

    public static void main(final String... args) throws IOException {
        if (args.length == 0) {
            System.out.println(USAGE);
            return;
        }

        Security.addProvider(new BouncyCastleProvider());

        try {
            execute(args);
        } catch (final RuntimeException e) {
            System.err.println(e.toString());
            e.printStackTrace(System.out);
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    private static void execute(final String... args) throws RuntimeException {
        final SigningArgs signingArgs = new SigningArgs();

        File destFile = null;

        File baseDir = null;
        File appBaseDir = null;
        String appDir = null;
        String appName = null;
        String appId = null;
        String teamId = null;
        String entitlements = null;
        String resourcesHash = null;
        String infoPlistHash = null;
        String resources256Hash = null;
        String infoPlist256Hash = null;
        Boolean isBundle = true;
        Boolean inPlace = false;

        final List<ApplicationArgs> appArgsList =
                new ArrayList<ApplicationArgs>();

        for (int i = 0; i < args.length; ++i) {
            final String argument = args[i];
            if (!argument.startsWith("-")) {
                if (destFile != null) {
                    throw new RuntimeException(
                            "Destination file already specified as '" + destFile + "', '" + argument + "' can't be used");
                } else if (inPlace) {
                    throw new RuntimeException(
                            "Destination file and in place both specified");
                }

                destFile = new File(argument);
                continue;
            }

            if (i == (args.length - 1)  && !argument.equals("--no_bundle") && !argument.equals("--in_place")) {
                throw new RuntimeException("Value missing for " + argument);
            }

            String value = null;
            if(!argument.equals("--no_bundle") && !argument.equals("--in_place")) {
                value = args[++i];
                if (value.startsWith("-")) {
                    throw new RuntimeException("Illegal value for " + argument);
                }
            }

            if ("-keystore".equalsIgnoreCase(argument)) {
                final File keyStore = new File(value);
                if (!keyStore.exists()) {
                    throw new RuntimeException("Keystore \"" + keyStore + "\" doesn't exist");
                }
                signingArgs.setKeyStore(keyStore);
            } else if ("-storepass".equalsIgnoreCase(argument)) {
                signingArgs.setStorePass(value);
            } else if ("-alias".equalsIgnoreCase(argument)) {
                signingArgs.setAlias(value);
            } else if ("-keypass".equalsIgnoreCase(argument)) {
                signingArgs.setKeyPass(value);
            } else if ("-basedir".equalsIgnoreCase(argument)) {
                baseDir = new File(value);
                if (!baseDir.isDirectory()) {
                    throw new RuntimeException("Base directory \"" + value + "\" doesn't exist");
                }
            } else if("-entitlements".equalsIgnoreCase(argument)) {
                final File entitlementsFile = new File(value);
                if (!entitlementsFile.exists()) {
                    throw new RuntimeException("Entitlements \"" + entitlementsFile + "\" doesn't exist");
                }
                entitlements = value;
            } else if ("-appdir".equalsIgnoreCase(argument)) {
                appDir = value;
                appBaseDir = baseDir;
            } else if ("-appname".equalsIgnoreCase(argument)) {
                appName = value;
            } else if ("-appid".equalsIgnoreCase(argument)) {
                appId = value;
            } else if ("-teamid".equalsIgnoreCase(argument)) {
                teamId = value;
            } else if ("-resources_hash".equalsIgnoreCase(argument)) {
                resourcesHash = value;
            } else if ("-info_plist_hash".equalsIgnoreCase(argument)) {
                infoPlistHash = value;
            } else if ("-resources_256_hash".equalsIgnoreCase(argument)) {
                resources256Hash = value;
            } else if ("-info_plist_256_hash".equalsIgnoreCase(argument)) {
                infoPlist256Hash = value;
            } else if ("--no_bundle".equalsIgnoreCase(argument)) {
                isBundle = false;
            } else if ("--in_place".equalsIgnoreCase(argument)) {
                inPlace = true;
                if (destFile != null) {
                    throw new RuntimeException(
                            "Destination file and in place both specified");
                }
            }
        }

        if ((appName != null) || (appId != null) || (appDir != null) || (teamId != null) || (entitlements != null) || (isBundle != null) || (inPlace != null) || (resourcesHash != null) || (infoPlistHash != null) || (resources256Hash != null) || (infoPlist256Hash != null)) {
            appArgsList.add(createApplicationArgs(
                                appBaseDir, appDir, appName, appId, teamId, entitlements, resourcesHash, infoPlistHash, resources256Hash, infoPlist256Hash, isBundle, inPlace));
        }

        if (destFile == null && !inPlace) {
            throw new RuntimeException("Destination file not specified");
        }

        if (appArgsList.isEmpty()) {
            throw new RuntimeException("No application specified");
        }

        signingArgs.validate();
        execute(destFile, signingArgs, appArgsList);
    }

    private static void execute(
            final File destFile,
            final SigningArgs signingArgs,
            final List<ApplicationArgs> appArgsList) throws RuntimeException {
        final Signer signer = createSigner(signingArgs);

        final Packer packer;

        final ApplicationArgs appArgs = appArgsList.get(0);
        try {
            packer = new Packer(destFile, signer, appArgs.getInPlace());
        } catch (final IOException e) {
            throw new RuntimeException(
                    constructExceptionMessage("Failed to create packer", e));
        }

        try {
            try {
                packer.storeApplication(
                        appArgs.getBaseDir(),
                        appArgs.getAppDir(),
                        appArgs.getAppName(),
                        appArgs.getAppId(),
                        appArgs.getTeamId(),
                        appArgs.getEntitlements(),
                        appArgs.getResourcesHash(),
                        appArgs.getInfoPlistHash(),
                        appArgs.getResources256Hash(),
                        appArgs.getInfoPlist256Hash(),
                        appArgs.getIsBundle());
            } catch (final IOException e) {
                throw new RuntimeException(
                        constructExceptionMessage(
                            "Failed to pack " + appArgs.getAppId(), e));
            }
        } finally {
            packer.close();
        }
    }

    private static ApplicationArgs createApplicationArgs(
            final File baseDir,
            final String appDir,
            final String appName,
            final String appId,
            final String teamId,
            final String entitlements,
            final String resourcesHash,
            final String infoPlistHash,
            final String resources256Hash,
            final String infoPlist256Hash,
            final Boolean isBundle,
            final Boolean inPlace) throws RuntimeException {
        final ApplicationArgs applicationArgs = new ApplicationArgs();
        if (baseDir != null) {
            applicationArgs.setBaseDir(baseDir);
        }
        if (appDir != null) {
            applicationArgs.setAppDir(appDir);
        }
        if (appName != null) {
            applicationArgs.setAppName(appName);
        }
        if (appId != null) {
            applicationArgs.setAppId(appId);
        }
        if (teamId != null) {
            applicationArgs.setTeamId(teamId);
        }
        if (entitlements != null) {
            applicationArgs.setEntitlements(entitlements);
        }
        if (resourcesHash != null) {
            applicationArgs.setResourcesHash(resourcesHash);
        }
        if (infoPlistHash != null) {
            applicationArgs.setInfoPlistHash(infoPlistHash);
        }
        if (resources256Hash != null) {
            applicationArgs.setResources256Hash(resources256Hash);
        }
        if (infoPlist256Hash != null) {
            applicationArgs.setInfoPlist256Hash(infoPlist256Hash);
        }
        if (isBundle != null) {
            applicationArgs.setIsBundle(isBundle);
        }
        if (inPlace != null) {
            applicationArgs.setInPlace(inPlace);
        }

        applicationArgs.validate();
        return applicationArgs;
    }

    private static Signer createSigner(final SigningArgs signingArgs)
            throws RuntimeException {
        Exception exception;
        try {
            return Signer.create(signingArgs.getKeyStore(),
                                 signingArgs.getStorePass(),
                                 signingArgs.getAlias(),
                                 signingArgs.getKeyPass());
        } catch (final KeyStoreException e) {
            exception = e;
        } catch (final NoSuchAlgorithmException e) {
            exception = e;
        } catch (final CertificateException e) {
            exception = e;
        } catch (final UnrecoverableKeyException e) {
            exception = e;
        } catch (final OperatorCreationException e) {
            exception = e;
        } catch (final CMSException e) {
            exception = e;
        } catch (final InvalidNameException e) {
            exception = e;
        } catch (final IOException e) {
            exception = e;
        }

        throw new RuntimeException(
                constructExceptionMessage("Failed to create signer",
                                          exception));
    }

    private static String constructExceptionMessage(
            final String mainMessage,
            final Exception exception) {
        final StringBuilder sb = new StringBuilder(mainMessage);
        final String nl = System.getProperty("line.separator");

        Throwable cause = exception;
        while (cause != null) {
            final String detail = cause.getMessage();
            if (detail != null) {
                sb.append(nl).append(detail);
            }

            cause = cause.getCause();
        }

        return sb.toString();
    }

    private static final class SigningArgs {
        private File keyStore;
        private String storePass;
        private String alias;
        private String keyPass;

        public SigningArgs() {
            storePass = "";
            keyPass = "";
        }

        public File getKeyStore() {
            return keyStore;
        }

        public void setKeyStore(final File keyStore) {
            this.keyStore = keyStore;
        }

        public String getStorePass() {
            return storePass;
        }

        public void setStorePass(final String storePass) {
            this.storePass = storePass;
        }

        public String getAlias() {
            return alias;
        }

        public void setAlias(final String alias) {
            this.alias = alias;
        }

        public String getKeyPass() {
            return keyPass;
        }

        public void setKeyPass(final String keyPass) {
            this.keyPass = keyPass;
        }

        public void validate() throws RuntimeException {
            if (keyStore == null) {
                throw new RuntimeException("Key store not specified");
            }

            if (alias == null) {
                throw new RuntimeException("Signing key not specified");
            }
        }
    }

    private static final class ApplicationArgs {
        private File baseDir;
        private String appDir;
        private String appName;
        private String appId;
        private String teamId;
        private String entitlements;
        private String resourcesHash;
        private String infoPlistHash;
        private String resources256Hash;
        private String infoPlist256Hash;
        private Boolean isBundle;
        private Boolean inPlace;

        public ApplicationArgs() {
            baseDir = new File("");
            appDir = "";
        }

        public File getBaseDir() {
            return baseDir;
        }

        public void setBaseDir(final File baseDir) {
            this.baseDir = baseDir;
        }

        public String getAppDir() {
            return appDir;
        }

        public void setAppDir(final String appDir) {
            this.appDir = appDir;
        }

        public String getAppName() {
            return appName;
        }

        public void setAppName(final String appName) {
            this.appName = appName;
        }

        public String getAppId() {
            return appId;
        }

        public void setAppId(final String appId) {
            this.appId = appId;
        }
        
        public String getTeamId() {
            return teamId;
        }

        public void setTeamId(final String teamId) {
            this.teamId = teamId;
        }

        public String getEntitlements() {
            return entitlements;
        }

        public void setEntitlements(final String entitlements) {
            this.entitlements = entitlements;
        }

        public String getResourcesHash() {
            return resourcesHash;
        }

        public void setResourcesHash(final String resourcesHash) {
            this.resourcesHash = resourcesHash;
        }

        public String getInfoPlistHash() {
            return infoPlistHash;
        }

        public void setInfoPlistHash(final String infoPlistHash) {
            this.infoPlistHash = infoPlistHash;
        }


        public String getResources256Hash() {
            return resources256Hash;
        }

        public void setResources256Hash(final String resources256Hash) {
            this.resources256Hash = resources256Hash;
        }

        public String getInfoPlist256Hash() {
            return infoPlist256Hash;
        }

        public void setInfoPlist256Hash(final String infoPlist256Hash) {
            this.infoPlist256Hash = infoPlist256Hash;
        }

        public Boolean getIsBundle() {
            return isBundle;
        }

        public void setIsBundle(final Boolean isBundle) {
            this.isBundle = isBundle;
        }

        public Boolean getInPlace() {
            return inPlace;
        }

        public void setInPlace(final Boolean inPlace) {
            this.inPlace = inPlace;
        }
        
        private final Boolean verifyHash(String hash, int length) {
            if (hash != null) {
                Pattern p = Pattern.compile("^[a-fA-F0-9]{" + length + "}$");
                Matcher m = p.matcher(hash);
                if (!m.find()) {
                    return false;
                }
            }
            return true;
        }

        public void validate() throws RuntimeException {
            final ResourceDescriptor appDirDescriptor =
                    new ResourceDescriptor(baseDir, appDir);

            if (!appDirDescriptor.getFile().exists()) {
                throw new RuntimeException("Directory \"" + appDir
                                               + "\" doesn't exist");
            }

            if (appName == null) {
                throw new RuntimeException(
                        "Application name not specified for " + appId);
            }

            final ResourceDescriptor appExeDescriptor =
                    new ResourceDescriptor(appDirDescriptor.getFile(),
                                           appName);
            if (!appExeDescriptor.getFile().exists()) {
                throw new RuntimeException(
                        "Application \"" + appName + "\" doesn't exist");
            }

            if (appId == null) {
                throw new RuntimeException(
                        "Application id not specified for " + appName);
            }

            if (teamId == null) {
                throw new RuntimeException(
                        "Team id not specified for " + appName);
            }

            Pattern p = Pattern.compile("^[a-zA-Z0-9]{10}$");
            Matcher m = p.matcher(teamId);
            if (!m.find()) {
                throw new RuntimeException(
                        "Team id must be 10 alphanumeric characters");
            }

            if (entitlements == null) {
                throw new RuntimeException(
                        "Entitlements not specified for " + appName);
            }

            if (!verifyHash(resourcesHash, 40)) {
                throw new RuntimeException("ResourcesHash must be 40 hexadecimal characters");
            }

            if (!verifyHash(infoPlistHash, 40)) {
                throw new RuntimeException("InfoPlistHash must be 40 hexadecimal characters");
            }

            if (!verifyHash(resources256Hash, 64)) {
                throw new RuntimeException("Resources256Hash must be 64 hexadecimal characters");
            }

            if (!verifyHash(infoPlist256Hash, 64)) {
                throw new RuntimeException("InfoPlist256Hash must be 64 hexadecimal characters");
            }

            // all ok, store normalized paths
            baseDir = appDirDescriptor.getBaseDir();
            appDir = appDirDescriptor.getRelativePath();
            appName = appExeDescriptor.getRelativePath();
        }
    }
}
