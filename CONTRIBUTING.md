# Contributing Guidelines

Thank you for your interest in contributing to this project. We welcome contributions that improve the tool's ability to help organizations comply with the EU Cyber Resilience Act.

## Standards and Principles

The core objective of this project is to provide reliable, automated compliance artifacts (SBOM and VEX). All contributions should prioritize:

1. Data Integrity: Ensure that SBOM merging and VEX generation maintain high fidelity to the source data.
2. Compliance Alignment: Changes should align with the technical requirements of the EU CRA and related standards (SPDX 2.3, CSAF 2.0).
3. Code Clarity: Maintain a modular architecture with well defined interfaces between configuration parsing, SBOM merging, and VEX generation.

## Development Workflow

### Environment Setup

This project uses Python 3.9 or higher. To set up your environment:

1. Clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies: `pip install -e ".[dev]"`

### Testing Requirements

We maintain a high standard for test coverage. All new features or bug fixes must include corresponding tests in the `tests/` directory.

Run tests using pytest:
`python -m pytest tests/ -v`

### Pull Request Process

1. Create a descriptive branch for your changes.
2. Ensure all tests pass locally.
3. Submit a Pull Request with a clear description of the problem solved or feature added.
4. Maintain a professional tone in all communications and documentation.

## Communication

Please use the issue tracker for bug reports and feature requests. For general discussions, refer to the project communication channels.
