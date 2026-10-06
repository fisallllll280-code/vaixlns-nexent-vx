# VAIXLNS Mathematical Engineering & Agent Readiness v0.2

This layer upgrades the existing Capability, Authority, Epistemic, Proof and VX
contracts with deterministic mathematical admission and routing.

## Mathematics

For normalized dimensions x_i in [0,1]:

R = exp(sum_i w_i ln(max(x_i, eps))) / (sum-normalized weights).

The weighted geometric mean makes a weak dimension visible instead of allowing
high scores elsewhere to hide it.

For k successful tests out of n trials, verification confidence uses the Wilson
lower bound:

p_L = [p + z^2/(2n) - z*sqrt(p(1-p)/n + z^2/(4n^2))] / [1 + z^2/n]

Expected failure loss is E[L] = sum(p_j * I_j).

Independent-impact blast radius is approximated by:
B = 1 - product(1 - w_j).

VX candidate routing uses:
U = alpha*S + beta*E + gamma*R + delta*Q - lambda*K - mu*C - nu*T

where S=capability similarity, E=evidence, R=readiness, Q=reliability,
K=risk, C=cost and T=latency.

The formulas are deterministic and dependency-free. Blast-radius is explicitly
an approximation and is not presented as a causal proof.
