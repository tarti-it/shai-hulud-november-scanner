// ============================================================================
// Scanner Sha1-Hulud - Détection de l'attaque supply-chain npm de novembre 2025
// ============================================================================
//
// DISQUES SCANNÉS : C:\, U:\, T:\ (intégralité)
//
// ============================================================================
// POINTS DE CONTRÔLE
// ============================================================================
//
// PACKAGES COMPROMIS [CRITIQUE]
//   Fichiers : package.json, package-lock.json, yarn.lock
//   Condition : Le package ET sa version exacte sont dans la base (802 packages)
//
// SCRIPTS SUSPECTS [HAUTE]
//   Fichiers : package.json (champs preinstall, postinstall, install)
//   Condition : Le script contient "setup_bun" OU "bun_environment" OU "bun "
//
// FICHIERS PAYLOAD [CRITIQUE]
//   Emplacement : Même répertoire que chaque package.json trouvé
//   Condition : Présence de "setup_bun.js" OU "bun_environment.js"
//
// FICHIERS D'EXFILTRATION [CRITIQUE si date > 18/11/2025]
//   Emplacement : Répertoire home (~/)
//   Condition : Présence de cloud.json, contents.json, environment.json,
//               truffleSecrets.json OU actionsSecrets.json
//
// PERSISTANCE GITHUB RUNNER [CRITIQUE]
//   Emplacement : Répertoire home (~/)
//   Condition : Présence du répertoire ~/.dev-env OU du fichier ~/.dev-env/.runner
//
// ============================================================================

package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

//go:embed packages_db.json
var embeddedDB embed.FS

type VulnerablePackage struct {
	VulnVers []string `json:"vuln_vers"`
}

type Detection struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	PackageName string `json:"package_name,omitempty"`
	Version     string `json:"version,omitempty"`
	Details     string `json:"details"`
	Severity    string `json:"severity"`
}

type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type PackageLockJSON struct {
	Packages     map[string]PackageLockEntry `json:"packages"`
	Dependencies map[string]PackageLockDep   `json:"dependencies"`
}

type PackageLockEntry struct {
	Version string `json:"version"`
}

type PackageLockDep struct {
	Version      string                    `json:"version"`
	Dependencies map[string]PackageLockDep `json:"dependencies"`
}

type Scanner struct {
	compromisedPackages map[string][]string
	maliciousFiles      []string
	iocFiles            []string
	detections          []Detection
	mutex               sync.Mutex
	scannedDirs         int
	scannedFiles        int
	verbose             bool
	dbSource            string
	reportedPackages    map[string]bool
	logFile             *os.File
}

// log écrit à la fois sur stdout et dans le fichier de log
func (s *Scanner) log(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Print(message)
	if s.logFile != nil {
		s.logFile.WriteString(message)
	}
}

// logln écrit une ligne à la fois sur stdout et dans le fichier de log
func (s *Scanner) logln(args ...interface{}) {
	message := fmt.Sprintln(args...)
	fmt.Print(message)
	if s.logFile != nil {
		s.logFile.WriteString(message)
	}
}

func NewScanner(verbose bool) (*Scanner, error) {
	s := &Scanner{
		compromisedPackages: make(map[string][]string),
		detections:          []Detection{},
		verbose:             verbose,
		reportedPackages:    make(map[string]bool),
	}

	if err := s.loadDatabase(); err != nil {
		return nil, err
	}

	s.loadStaticIndicators()
	return s, nil
}

func (s *Scanner) loadDatabase() error {
	data, err := embeddedDB.ReadFile("packages_db.json")
	if err != nil {
		return fmt.Errorf("no database found. Name: packages_db.json")
	}
	s.dbSource = "embedded"

	var db map[string]VulnerablePackage
	if err := json.Unmarshal(data, &db); err != nil {
		return fmt.Errorf("failed to parse database JSON: %w", err)
	}

	for pkgName, pkgInfo := range db {
		s.compromisedPackages[pkgName] = pkgInfo.VulnVers
	}

	return nil
}

func (s *Scanner) loadStaticIndicators() {
	s.maliciousFiles = []string{
		"setup_bun.js",
		"bun_environment.js",
	}

	s.iocFiles = []string{
		"cloud.json",
		"contents.json",
		"environment.json",
		"truffleSecrets.json",
		"actionsSecrets.json",
	}
}

func (s *Scanner) addDetection(d Detection) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	key := fmt.Sprintf("%s@%s", d.PackageName, d.Version)
	if d.PackageName != "" && s.reportedPackages[key] {
		return
	}
	if d.PackageName != "" {
		s.reportedPackages[key] = true
	}

	s.detections = append(s.detections, d)
}

func (s *Scanner) incrementScanned(isDir bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if isDir {
		s.scannedDirs++
	} else {
		s.scannedFiles++
	}
}

func (s *Scanner) isCompromised(pkgName, version string) bool {
	versions, found := s.compromisedPackages[pkgName]
	if !found {
		return false
	}
	if len(versions) == 0 {
		return true
	}
	return contains(versions, version)
}

func (s *Scanner) checkPackageJSON(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return
	}

	packageDir := filepath.Dir(path)

	if s.isCompromised(pkg.Name, pkg.Version) {
		s.addDetection(Detection{
			Type:        "compromised_package",
			Path:        path,
			PackageName: pkg.Name,
			Version:     pkg.Version,
			Details:     "Package is in the known compromised list",
			Severity:    "critical",
		})
	}

	suspiciousScripts := []string{"preinstall", "postinstall", "install"}
	for _, scriptName := range suspiciousScripts {
		if script, exists := pkg.Scripts[scriptName]; exists {
			if strings.Contains(script, "setup_bun") ||
				strings.Contains(script, "bun_environment") ||
				strings.Contains(script, "bun ") {
				s.addDetection(Detection{
					Type:        "suspicious_script",
					Path:        path,
					PackageName: pkg.Name,
					Version:     pkg.Version,
					Details:     fmt.Sprintf("Suspicious %s script: %s", scriptName, truncate(script, 100)),
					Severity:    "high",
				})
			}
		}
	}

	for _, malFile := range s.maliciousFiles {
		malPath := filepath.Join(packageDir, malFile)
		if info, err := os.Stat(malPath); err == nil {
			sizeInfo := ""
			if info.Size() > 5*1024*1024 {
				sizeInfo = fmt.Sprintf(" (large file: %.2f MB - typical for obfuscated payload)", float64(info.Size())/(1024*1024))
			}
			s.addDetection(Detection{
				Type:        "malicious_file",
				Path:        malPath,
				PackageName: pkg.Name,
				Version:     pkg.Version,
				Details:     fmt.Sprintf("Malicious payload file detected%s", sizeInfo),
				Severity:    "critical",
			})
		}
	}
}

func (s *Scanner) checkPackageLockJSON(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var lockfile PackageLockJSON
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return
	}

	for pkgPath, entry := range lockfile.Packages {
		pkgName := extractPackageName(pkgPath)
		if pkgName == "" {
			continue
		}

		if s.isCompromised(pkgName, entry.Version) {
			s.addDetection(Detection{
				Type:        "compromised_dependency",
				Path:        path,
				PackageName: pkgName,
				Version:     entry.Version,
				Details:     "Compromised package found in package-lock.json (transitive dependency)",
				Severity:    "critical",
			})
		}
	}

	s.checkLockfileDepsRecursive(path, lockfile.Dependencies)
}

func (s *Scanner) checkLockfileDepsRecursive(path string, deps map[string]PackageLockDep) {
	for pkgName, dep := range deps {
		if s.isCompromised(pkgName, dep.Version) {
			s.addDetection(Detection{
				Type:        "compromised_dependency",
				Path:        path,
				PackageName: pkgName,
				Version:     dep.Version,
				Details:     "Compromised package found in package-lock.json (transitive dependency)",
				Severity:    "critical",
			})
		}
		if dep.Dependencies != nil {
			s.checkLockfileDepsRecursive(path, dep.Dependencies)
		}
	}
}

func (s *Scanner) checkYarnLock(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	content := string(data)
	entryRegex := regexp.MustCompile(`(?m)^["']?(@?[^@\s"']+)@[^"'\s:]+["']?.*:\s*\n\s+version\s+["']([^"']+)["']`)

	matches := entryRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			pkgName := match[1]
			version := match[2]

			if s.isCompromised(pkgName, version) {
				s.addDetection(Detection{
					Type:        "compromised_dependency",
					Path:        path,
					PackageName: pkgName,
					Version:     version,
					Details:     "Compromised package found in yarn.lock (transitive dependency)",
					Severity:    "critical",
				})
			}
		}
	}
}

func extractPackageName(path string) string {
	if path == "" {
		return ""
	}

	path = strings.TrimPrefix(path, "node_modules/")

	if strings.HasPrefix(path, "@") {
		parts := strings.SplitN(path, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}

	parts := strings.SplitN(path, "/", 2)
	if len(parts) >= 1 && parts[0] != "" {
		return parts[0]
	}

	return ""
}

func (s *Scanner) checkForIOCFiles(dir string) {
	for _, iocFile := range s.iocFiles {
		iocPath := filepath.Join(dir, iocFile)
		if info, err := os.Stat(iocPath); err == nil {
			modTime := info.ModTime()
			attackStart := time.Date(2025, 11, 18, 0, 0, 0, 0, time.UTC)

			severity := "medium"
			details := "IOC file created by Sha1-Hulud malware"
			if modTime.After(attackStart) {
				severity = "critical"
				details = fmt.Sprintf("IOC file created during attack window (modified: %s)", modTime.Format("2006-01-02 15:04:05"))
			}

			s.addDetection(Detection{
				Type:     "ioc_file",
				Path:     iocPath,
				Details:  details,
				Severity: severity,
			})
		}
	}
}

func (s *Scanner) checkForGitHubRunner(homeDir string) {
	devEnvPath := filepath.Join(homeDir, ".dev-env")
	if _, err := os.Stat(devEnvPath); err == nil {
		s.addDetection(Detection{
			Type:     "persistence",
			Path:     devEnvPath,
			Details:  "Suspicious .dev-env directory (used by Sha1-Hulud for GitHub Actions runner persistence)",
			Severity: "critical",
		})
	}

	runnerConfig := filepath.Join(devEnvPath, ".runner")
	if _, err := os.Stat(runnerConfig); err == nil {
		s.addDetection(Detection{
			Type:     "persistence",
			Path:     runnerConfig,
			Details:  "GitHub Actions runner configuration detected",
			Severity: "critical",
		})
	}
}

func (s *Scanner) scanDirectory(root string, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()

	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			s.incrementScanned(true)
			return nil
		}

		fileName := d.Name()

		switch fileName {
		case "package.json":
			s.incrementScanned(false)
			if s.verbose {
				fmt.Printf("\r[*] Checking: %s", truncate(path, 80))
			}
			s.checkPackageJSON(path)

		case "package-lock.json":
			s.incrementScanned(false)
			if s.verbose {
				fmt.Printf("\r[*] Checking: %s", truncate(path, 80))
			}
			s.checkPackageLockJSON(path)

		case "yarn.lock":
			s.incrementScanned(false)
			if s.verbose {
				fmt.Printf("\r[*] Checking: %s", truncate(path, 80))
			}
			s.checkYarnLock(path)
		}

		return nil
	})
}

func (s *Scanner) Scan() {
	s.logln("╔════════════════════════════════════════════════════════════════╗")
	s.logln("║     Sha1-Hulud NPM Supply Chain Attack Scanner                 ║")
	s.logln("║     November 2025 Campaign Detection                           ║")
	s.logln("╚════════════════════════════════════════════════════════════════╝")
	s.logln()
	s.logln("DISQUES SCANNÉS : C:\\, U:\\, T:\\ (intégralité)")
	s.logln()
	s.logln("POINTS DE CONTRÔLE :")
	s.logln()
	s.logln("  PACKAGES COMPROMIS [CRITIQUE]")
	s.logln("    Fichiers : package.json, package-lock.json, yarn.lock")
	s.logln("    Condition : Le package ET sa version exacte sont dans la base (802 packages)")
	s.logln()
	s.logln("  SCRIPTS SUSPECTS [HAUTE]")
	s.logln("    Fichiers : package.json (champs preinstall, postinstall, install)")
	s.logln("    Condition : Le script contient \"setup_bun\" OU \"bun_environment\" OU \"bun \"")
	s.logln()
	s.logln("  FICHIERS PAYLOAD [CRITIQUE]")
	s.logln("    Emplacement : Même répertoire que chaque package.json trouvé")
	s.logln("    Condition : Présence de \"setup_bun.js\" OU \"bun_environment.js\"")
	s.logln()
	s.logln("  FICHIERS D'EXFILTRATION [CRITIQUE si date > 18/11/2025]")
	s.logln("    Emplacement : Répertoire home (~/)")
	s.logln("    Condition : Présence de cloud.json, contents.json, environment.json,")
	s.logln("                truffleSecrets.json OU actionsSecrets.json")
	s.logln()
	s.logln("  PERSISTANCE GITHUB RUNNER [CRITIQUE]")
	s.logln("    Emplacement : Répertoire home (~/)")
	s.logln("    Condition : Présence du répertoire ~/.dev-env OU du fichier ~/.dev-env/.runner")
	s.logln()
	s.logln("════════════════════════════════════════════════════════════════")
	s.logln()

	startTime := time.Now()

	s.log("[*] Database: %s (%d packages)\n", s.dbSource, len(s.compromisedPackages))
	s.logln("[*] Scanning: package.json, package-lock.json, yarn.lock")

	paths := s.getDefaultPaths()

	s.log("[*] Scanning %d path(s)...\n", len(paths))
	for _, p := range paths {
		s.log("    - %s\n", p)
	}
	s.logln()

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		s.checkForIOCFiles(homeDir)
		s.checkForGitHubRunner(homeDir)
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			wg.Add(1)
			go s.scanDirectory(path, &wg, semaphore)
		}
	}

	wg.Wait()

	if s.verbose {
		fmt.Printf("\r%80s\r", "")
	}

	elapsed := time.Since(startTime)
	s.printResults(elapsed)
}

func (s *Scanner) getDefaultPaths() []string {
	var paths []string

	if runtime.GOOS == "windows" {
		drives := []string{"C:\\", "U:\\", "T:\\"}
		for _, drive := range drives {
			if _, err := os.Stat(drive); err == nil {
				paths = append(paths, drive)
			}
		}
	}

	return paths
}

func (s *Scanner) printResults(elapsed time.Duration) {
	s.logln()
	s.logln("════════════════════════════════════════════════════════════════")
	s.logln("                         SCAN RESULTS")
	s.logln("════════════════════════════════════════════════════════════════")
	s.log("Directories scanned: %d\n", s.scannedDirs)
	s.log("Files analyzed: %d (package.json + lockfiles)\n", s.scannedFiles)
	s.log("Time elapsed: %v\n", elapsed.Round(time.Millisecond))
	s.logln()

	if len(s.detections) == 0 {
		s.logln("✅ No Sha1-Hulud indicators detected!")
		s.logln()
		return
	}

	critical := []Detection{}
	high := []Detection{}
	medium := []Detection{}

	for _, d := range s.detections {
		switch d.Severity {
		case "critical":
			critical = append(critical, d)
		case "high":
			high = append(high, d)
		default:
			medium = append(medium, d)
		}
	}

	s.log("⚠️  DETECTIONS FOUND: %d\n", len(s.detections))
	s.log("   Critical: %d | High: %d | Medium: %d\n", len(critical), len(high), len(medium))
	s.logln()

	if len(critical) > 0 {
		s.logln("🔴 CRITICAL RISK FINDINGS:")
		s.logln("────────────────────────────────────────────────────────────────")
		for _, d := range critical {
			s.printDetection(d)
		}
	}

	if len(high) > 0 {
		s.logln("🟠 HIGH RISK FINDINGS:")
		s.logln("────────────────────────────────────────────────────────────────")
		for _, d := range high {
			s.printDetection(d)
		}
	}

	if len(medium) > 0 {
		s.logln("🟡 MEDIUM RISK FINDINGS:")
		s.logln("────────────────────────────────────────────────────────────────")
		for _, d := range medium {
			s.printDetection(d)
		}
	}
}

func (s *Scanner) printDetection(d Detection) {
	s.log("  Type: %s\n", d.Type)
	s.log("  Path: %s\n", d.Path)
	if d.PackageName != "" {
		s.log("  Package: %s@%s\n", d.PackageName, d.Version)
	}
	s.log("  Details: %s\n", d.Details)
	s.logln()
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func truncate(str string, maxLen int) string {
	if len(str) <= maxLen {
		return str
	}
	return str[:maxLen-3] + "..."
}

func main() {
	verbose := flag.Bool("v", true, "Verbose output")
	flag.Parse()

	scanner, err := NewScanner(*verbose)
	if err != nil {
		fmt.Printf("Error initializing scanner: %v\n", err)
		fmt.Println("\nUsage:")
		fmt.Println("Place packages_db.json next to the executable")
		fmt.Println("\nAppuyez sur Entrée pour fermer...")
		fmt.Scanln()
		os.Exit(1)
	}

	// Créer le fichier de log
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	if username == "" {
		username = "unknown"
	}
	if hostname == "" {
		hostname = "unknown"
	}

	// Format: utilisateur_machine_2025-11-27_14-30-05.txt
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logFileName := fmt.Sprintf("%s_%s_%s.txt", username, hostname, timestamp)
	logFile, err := os.Create(logFileName)
	if err != nil {
		fmt.Printf("Warning: Could not create log file: %v\n", err)
	} else {
		scanner.logFile = logFile
		defer logFile.Close()
	}

	scanner.Scan()

	if scanner.logFile != nil {
		scanner.log("\n[*] Log saved to: %s\n", logFileName)
	}

	fmt.Println("\nAppuyez sur Entrée pour fermer...")
	fmt.Scanln()
}
